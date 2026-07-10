from __future__ import annotations

import argparse
import json
from pathlib import Path

from .benchmark import BenchmarkConfig, BenchmarkRunner
from .config import AuditConfig
from .integration import run_integration_preflight, run_integration_smoke
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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = AuditConfig.from_json(args.config) if args.config else AuditConfig.default()
    if getattr(args, "validation_level", None):
        config.default_validation_level = args.validation_level
    _apply_runtime_args(config, args)

    if args.command == "scan":
        result = run_audit(args.target, config, args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "benchmark":
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
        return 0
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


def _add_integration_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--llm", action="store_true", help="Include LLM provider preflight.")
    parser.add_argument("--mcp", action="store_true", help="Include CVE MCP preflight.")
    parser.add_argument("--live", action="store_true", help="Perform live calls instead of config-only checks.")
    parser.add_argument("--llm-decisions", action="store_true", help="Enable guarded LLM decision participation during smoke.")
    parser.add_argument("--llm-decision-roles", default=None, help="Comma-separated roles enabled for LLM decisions.")
    parser.add_argument("--output", default="runs", help="Run output directory.")


if __name__ == "__main__":
    raise SystemExit(main())
