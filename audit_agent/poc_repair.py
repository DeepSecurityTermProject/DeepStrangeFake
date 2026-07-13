from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import AuditConfig
from .llm import LLMClient, LLMProviderError
from .models import (
    Finding,
    LLMRequest,
    PoCArtifact,
    PoCEditableSlot,
    PoCFailureClass,
    PoCFailureClassification,
    PoCNormalizedEdit,
    PoCProtectedNode,
    PoCRepairManifest,
    PoCRepairRecord,
    PoCSafetyDecision,
    PoCSemanticIntegrityDecision,
    RepairStopReason,
    RepositoryMetadata,
    SandboxRunResult,
    TargetFileManifest,
    TargetIntegrityComparison,
)
from .prompts import default_prompt_registry, persist_prompt
from .redaction import redact_secrets, redact_text
from .storage import immutable_path


IMPORT_SLOT_BEGIN = "# POC_REPAIR_SLOT:imports:begin"
IMPORT_SLOT_END = "# POC_REPAIR_SLOT:imports:end"
SETUP_SLOT_BEGIN = "# POC_REPAIR_SLOT:setup:begin"
SETUP_SLOT_END = "# POC_REPAIR_SLOT:setup:end"
SAFE_IMPORT_MODULES = {"json", "math", "os", "pathlib", "re", "sqlite3", "typing"}
PROTECTED_MARKERS = {
    "PATH_TRAVERSAL_CONFIRMED",
    "PATH_TRAVERSAL_BLOCKED",
    "SQLI_CONFIRMED",
    "SQLI_REJECTED",
}
DENIED_IMPORT_ROOTS = {
    "asyncio",
    "ctypes",
    "ftplib",
    "http",
    "importlib",
    "multiprocessing",
    "paramiko",
    "pip",
    "requests",
    "shutil",
    "smtplib",
    "socket",
    "subprocess",
    "telnetlib",
    "urllib",
}
DENIED_CALLS = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.fork",
    "os.popen",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}


class PoCRepairContractError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class ParsedPoCRepairResponse:
    diagnosis: str
    edits: list[PoCNormalizedEdit]
    changes: list[str]
    edit_hash: str


@dataclass
class RepairAgentResult:
    record: PoCRepairRecord
    proposal: ParsedPoCRepairResponse | None = None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_text(encoded)


def build_and_persist_repair_manifest(
    *,
    finding_id: str,
    generator_id: str,
    script_text: str,
    attempt_dir: str | Path,
    expected_signal: dict[str, Any],
    editable_slots: list[PoCEditableSlot] | None = None,
) -> PoCRepairManifest:
    slots = editable_slots if editable_slots is not None else editable_slots_from_script(script_text)
    protected_nodes = protected_nodes_from_script(script_text, slots)
    expected_markers = sorted(
        {
            str(expected_signal.get("value") or ""),
            str(expected_signal.get("rejected_value") or ""),
        }
        - {""}
    )
    result_names = sorted({str(expected_signal.get("result_filename") or "")} - {""})
    manifest = PoCRepairManifest(
        finding_id=finding_id,
        generator_id=generator_id,
        script_hash=sha256_text(script_text),
        editable_slots=slots,
        protected_nodes=protected_nodes,
        expected_markers=expected_markers,
        protected_result_filenames=result_names,
    )
    manifest.manifest_hash = manifest_hash(manifest)
    path = immutable_path(Path(attempt_dir) / "repair-manifest.json")
    manifest.metadata_path = str(path)
    path.write_text(json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def editable_slots_from_script(script_text: str) -> list[PoCEditableSlot]:
    slots: list[PoCEditableSlot] = []
    if IMPORT_SLOT_BEGIN in script_text and IMPORT_SLOT_END in script_text:
        slots.append(
            PoCEditableSlot(
                slot_id="imports",
                operations=["add_import"],
                start_marker=IMPORT_SLOT_BEGIN,
                end_marker=IMPORT_SLOT_END,
                purpose="imports",
                allowed_values=sorted(SAFE_IMPORT_MODULES),
                max_value_length=200,
            )
        )
    if SETUP_SLOT_BEGIN in script_text and SETUP_SLOT_END in script_text:
        slots.append(
            PoCEditableSlot(
                slot_id="setup",
                operations=["replace_slot"],
                start_marker=SETUP_SLOT_BEGIN,
                end_marker=SETUP_SLOT_END,
                purpose="target-derived-setup",
                max_value_length=2000,
            )
        )
    return slots


def protected_nodes_from_script(
    script_text: str, slots: list[PoCEditableSlot]
) -> list[PoCProtectedNode]:
    try:
        tree = ast.parse(script_text)
    except SyntaxError:
        return []
    ranges = _slot_line_ranges(script_text, slots)
    occurrences: Counter[str] = Counter()
    protected: list[PoCProtectedNode] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt) or not hasattr(node, "lineno"):
            continue
        start = int(getattr(node, "lineno", 0) or 0)
        end = int(getattr(node, "end_lineno", start) or start)
        if _inside_any_slot(start, end, ranges):
            continue
        digest = _ast_hash(node)
        occurrences[digest] += 1
        category = _protected_category(node)
        node_id = f"{category}-{digest[:12]}-{occurrences[digest]}"
        literals = sorted(
            {
                str(item.value)
                for item in ast.walk(node)
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
        )
        protected.append(
            PoCProtectedNode(
                node_id=node_id,
                node_type=type(node).__name__,
                ast_hash=digest,
                category=category,
                source_location={"line": start, "end_line": end},
                literals=literals,
            )
        )
    return sorted(protected, key=lambda item: (item.source_location.get("line", 0), item.node_id))


def manifest_hash(manifest: PoCRepairManifest) -> str:
    return canonical_hash(
        {
            "manifest_version": manifest.manifest_version,
            "finding_id": manifest.finding_id,
            "generator_id": manifest.generator_id,
            "script_hash": manifest.script_hash,
            "editable_slots": [item.to_dict() for item in manifest.editable_slots],
            "protected_nodes": [item.to_dict() for item in manifest.protected_nodes],
            "expected_markers": manifest.expected_markers,
            "protected_result_filenames": manifest.protected_result_filenames,
        }
    )


def load_repair_manifest(path: str | Path) -> PoCRepairManifest:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest = PoCRepairManifest(
        finding_id=str(payload["finding_id"]),
        generator_id=str(payload["generator_id"]),
        script_hash=str(payload["script_hash"]),
        editable_slots=[PoCEditableSlot(**item) for item in payload.get("editable_slots", [])],
        protected_nodes=[PoCProtectedNode(**item) for item in payload.get("protected_nodes", [])],
        expected_markers=list(payload.get("expected_markers", [])),
        protected_result_filenames=list(payload.get("protected_result_filenames", [])),
        manifest_version=str(payload.get("manifest_version") or "poc-repair-manifest.v1"),
        manifest_hash=str(payload.get("manifest_hash") or ""),
        metadata_path=str(path),
        created_at=str(payload.get("created_at") or ""),
        id=payload.get("id"),
    )
    expected_hash = manifest_hash(manifest)
    if not manifest.manifest_hash or manifest.manifest_hash != expected_hash:
        raise ValueError("repair manifest hash mismatch")
    return manifest


def persist_execution_envelope(poc: PoCArtifact, attempt_dir: str | Path) -> str:
    payload = execution_envelope_payload(poc)
    digest = canonical_hash(payload)
    path = immutable_path(Path(attempt_dir) / "execution-envelope.json")
    path.write_text(
        json.dumps({"envelope_hash": digest, **payload}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    poc.immutable_envelope_hash = digest
    poc.immutable_envelope_ref = str(path)
    return str(path)


def execution_envelope_payload(poc: PoCArtifact) -> dict[str, Any]:
    return {
        "finding_id": poc.finding_id,
        "vulnerability_class": poc.vulnerability_class,
        "generator_id": poc.generator_id,
        "expected_signal": poc.expected_signal,
        "safety_profile": {
            key: value
            for key, value in poc.safety_profile.items()
            if key not in {"repair_applied", "repair_attempt_index"}
        },
        "source_refs": poc.source_refs,
        "dataflow_trace_refs": poc.dataflow_trace_refs,
        "target_file_refs": poc.target_file_refs,
        "repair_manifest_hash": poc.repair_manifest_hash,
        "protected_node_hashes": poc.protected_node_hashes,
        "command_shape": ["python", "<attempt-script>"],
    }


def parse_poc_repair_response(
    value: Any,
    manifest: PoCRepairManifest,
    *,
    max_edits: int = 10,
    max_changes: int = 20,
) -> ParsedPoCRepairResponse:
    errors: list[str] = []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PoCRepairContractError([f"response must be strict JSON: {exc.msg}"]) from exc
    if not isinstance(value, dict):
        raise PoCRepairContractError(["response must be an object"])
    expected_top = {"diagnosis", "edits", "changes"}
    _check_exact_keys(value, expected_top, "response", errors)
    diagnosis = _bounded_string(value.get("diagnosis"), "diagnosis", 2000, errors)
    raw_edits = value.get("edits")
    if not isinstance(raw_edits, list):
        errors.append("edits must be an array")
        raw_edits = []
    elif not 1 <= len(raw_edits) <= max_edits:
        errors.append(f"edits must contain 1..{max_edits} items")
    raw_changes = value.get("changes")
    changes: list[str] = []
    if not isinstance(raw_changes, list):
        errors.append("changes must be an array")
    elif not 1 <= len(raw_changes) <= max_changes:
        errors.append(f"changes must contain 1..{max_changes} items")
    else:
        for index, item in enumerate(raw_changes):
            changes.append(_bounded_string(item, f"changes[{index}]", 500, errors))

    slots = {slot.slot_id: slot for slot in manifest.editable_slots}
    normalized: list[PoCNormalizedEdit] = []
    seen_targets: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_edits):
        label = f"edits[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{label} must be an object")
            continue
        op = raw.get("op")
        slot_id = raw.get("slot_id")
        if not isinstance(op, str) or not op:
            errors.append(f"{label}.op must be a non-empty string")
            continue
        if not isinstance(slot_id, str) or not slot_id:
            errors.append(f"{label}.slot_id must be a non-empty string")
            continue
        slot = slots.get(slot_id)
        if slot is None:
            errors.append(f"{label}.slot_id is not declared by the repair manifest: {slot_id}")
            continue
        if op not in slot.operations:
            errors.append(f"{label}.op {op} is not allowed for slot {slot_id}")
            continue
        target = (op, slot_id)
        if target in seen_targets:
            errors.append(f"duplicate or conflicting edit for {op}:{slot_id}")
            continue
        seen_targets.add(target)
        if op == "add_import":
            allowed_keys = {"op", "slot_id", "module"}
            if "name" in raw:
                allowed_keys.add("name")
            _check_exact_keys(raw, allowed_keys, label, errors)
            module = _bounded_string(raw.get("module"), f"{label}.module", 100, errors)
            name = None
            if "name" in raw:
                name = _bounded_string(raw.get("name"), f"{label}.name", 100, errors)
            if module and not all(part.isidentifier() for part in module.split(".")):
                errors.append(f"{label}.module must be a dotted Python identifier")
            allowed_modules = set(slot.allowed_values or SAFE_IMPORT_MODULES)
            if module and module.split(".")[0] not in allowed_modules:
                errors.append(f"{label}.module is not allowlisted: {module}")
            if name and not name.isidentifier():
                errors.append(f"{label}.name must be a Python identifier")
            normalized.append(PoCNormalizedEdit(op=op, slot_id=slot_id, module=module, name=name))
        elif op == "replace_slot":
            _check_exact_keys(raw, {"op", "slot_id", "value"}, label, errors)
            replacement = _bounded_string(raw.get("value"), f"{label}.value", slot.max_value_length, errors)
            if "POC_REPAIR_SLOT:" in replacement:
                errors.append(f"{label}.value cannot contain repair slot markers")
            normalized.append(PoCNormalizedEdit(op=op, slot_id=slot_id, value=replacement))
        else:
            errors.append(f"unknown edit operation: {op}")
    if errors:
        raise PoCRepairContractError(errors)
    normalized_payload = [item.to_dict() for item in normalized]
    return ParsedPoCRepairResponse(
        diagnosis=diagnosis,
        edits=normalized,
        changes=changes,
        edit_hash=canonical_hash(normalized_payload),
    )


def build_repair_context(
    *,
    poc: PoCArtifact,
    manifest: PoCRepairManifest,
    sandbox_result: SandboxRunResult,
    judge_reason: str,
    finding: Finding,
    metadata: RepositoryMetadata,
    attempt_index: int,
    remaining_budget: int,
    secret_values: list[str] | None = None,
) -> dict[str, Any]:
    secrets = secret_values or []
    prior_script = _bounded_read(Path(poc.script_path), 24000)
    diagnostics = "\n".join(
        filter(
            None,
            [
                sandbox_result.stderr_preview,
                sandbox_result.stdout_preview,
                _bounded_read(Path(sandbox_result.stderr_ref), 4000) if sandbox_result.stderr_ref else "",
                _bounded_read(Path(sandbox_result.stdout_ref), 4000) if sandbox_result.stdout_ref else "",
            ],
        )
    )
    trace_contexts = []
    for ref in poc.dataflow_trace_refs[:3]:
        path = Path(ref)
        if path.is_file():
            trace_contexts.append(_bounded_read(path, 8000))
    snippets = _grounded_source_snippets(finding, metadata, poc.dataflow_trace_refs)
    manifest_payload = manifest.to_dict()
    manifest_payload.pop("metadata_path", None)
    return redact_secrets(
        {
            "prior_script": prior_script,
            "repair_manifest": manifest_payload,
            "diagnostics": diagnostics[:12000],
            "dataflow_context": "\n".join(trace_contexts)[:12000],
            "source_sink_snippets": snippets[:12000],
            "missing_evidence": str(judge_reason)[:2000],
            "attempt_index": attempt_index,
            "remaining_budget": remaining_budget,
        },
        secrets,
    )


class LLMPoCRepairAgent:
    def __init__(
        self,
        llm_client: LLMClient,
        config: AuditConfig,
        run_dir: str | Path,
        message_bus: Any | None = None,
    ):
        self.llm_client = llm_client
        self.config = config
        self.run_dir = Path(run_dir)
        self.message_bus = message_bus
        self.secret_values = _configured_secret_values(config)

    def repair(
        self,
        *,
        context: dict[str, Any],
        manifest: PoCRepairManifest,
        finding_id: str,
        attempt_index: int,
        remaining_budget: int,
        attempt_dir: str | Path,
    ) -> RepairAgentResult:
        attempt_dir = Path(attempt_dir)
        attempt_dir.mkdir(parents=True, exist_ok=True)
        record = default_prompt_registry().render("poc-repair.edits", "v1", context)
        prompt_ref = persist_prompt(self.run_dir / "prompts", record)
        request = LLMRequest(
            role="poc-repair",
            prompt=record.rendered,
            model=self.config.llm.model,
            provider=self.config.llm.provider,
            temperature=0.0,
            max_tokens=min(self.config.llm.max_tokens, 2048),
            response_schema=record.output_schema,
            response_format="auto",
            metadata={
                "template_id": "poc-repair.edits",
                "template_version": "v1",
                "finding_id": finding_id,
                "attempt_index": attempt_index,
                "remaining_budget": remaining_budget,
                "repair_manifest_hash": manifest.manifest_hash,
            },
        )
        self._publish(
            "poc.repair.request",
            {
                "finding_id": finding_id,
                "attempt_index": attempt_index,
                "manifest_hash": manifest.manifest_hash,
                "prompt_ref": str(prompt_ref),
            },
            [str(prompt_ref)],
        )
        try:
            response = self.llm_client.complete(request)
        except LLMProviderError as exc:
            failed = PoCRepairRecord(
                finding_id=finding_id,
                attempt_index=attempt_index,
                status="provider-failed",
                prompt_ref=str(prompt_ref),
                manifest_ref=manifest.metadata_path,
                provider_metadata=exc.to_dict(),
                validation_errors=[str(exc)],
                stop_reason=RepairStopReason.PROVIDER_FAILURE,
            )
            _persist_record(failed, attempt_dir / "repair-record.json")
            self._publish(
                "poc.repair.provider-failed",
                {"finding_id": finding_id, "attempt_index": attempt_index, "stop_reason": failed.stop_reason.value},
                [failed.metadata_path or ""],
            )
            return RepairAgentResult(record=failed)
        provider_metadata = {
            "provider": response.provider,
            "model": response.model,
            "usage": response.usage,
            "finish_reason": response.finish_reason,
            "latency_ms": response.latency_ms,
        }
        try:
            proposal = parse_poc_repair_response(
                response.parsed_json if response.parsed_json is not None else response.text,
                manifest,
            )
        except PoCRepairContractError as exc:
            response_ref = self._persist_normalized_response(
                request.id or "request",
                {
                    "status": "invalid-contract",
                    "validation_errors": exc.errors,
                    "provider": provider_metadata,
                    "redacted_text": redact_text(response.text, self.secret_values),
                },
            )
            failed = PoCRepairRecord(
                finding_id=finding_id,
                attempt_index=attempt_index,
                status="invalid-contract",
                prompt_ref=str(prompt_ref),
                response_ref=str(response_ref),
                manifest_ref=manifest.metadata_path,
                provider_metadata=provider_metadata,
                validation_errors=exc.errors,
                stop_reason=RepairStopReason.INVALID_CONTRACT,
            )
            _persist_record(failed, attempt_dir / "repair-record.json")
            self._publish(
                "poc.repair.contract-denied",
                {
                    "finding_id": finding_id,
                    "attempt_index": attempt_index,
                    "errors": exc.errors,
                    "stop_reason": failed.stop_reason.value,
                },
                [str(response_ref), failed.metadata_path or ""],
            )
            return RepairAgentResult(record=failed)
        response_ref = self._persist_normalized_response(
            request.id or "request",
            {
                "status": "validated",
                "diagnosis": redact_text(proposal.diagnosis, self.secret_values),
                "edits": [item.to_dict() for item in proposal.edits],
                "changes": [redact_text(item, self.secret_values) for item in proposal.changes],
                "edit_hash": proposal.edit_hash,
                "provider": provider_metadata,
            },
        )
        successful = PoCRepairRecord(
            finding_id=finding_id,
            attempt_index=attempt_index,
            status="validated",
            diagnosis=redact_text(proposal.diagnosis, self.secret_values),
            changes=[redact_text(item, self.secret_values) for item in proposal.changes],
            normalized_edits=proposal.edits,
            prompt_ref=str(prompt_ref),
            response_ref=str(response_ref),
            edit_hash=proposal.edit_hash,
            manifest_ref=manifest.metadata_path,
            provider_metadata=provider_metadata,
        )
        _persist_record(successful, attempt_dir / "repair-record.json")
        self._publish(
            "poc.repair.response",
            {
                "finding_id": finding_id,
                "attempt_index": attempt_index,
                "edit_hash": proposal.edit_hash,
                "status": "validated",
            },
            [str(response_ref), successful.metadata_path or ""],
        )
        return RepairAgentResult(record=successful, proposal=proposal)

    def _persist_normalized_response(self, request_id: str, payload: dict[str, Any]) -> Path:
        root = self.run_dir / "llm"
        root.mkdir(parents=True, exist_ok=True)
        path = immutable_path(root / f"poc-repair-{request_id}.json")
        path.write_text(
            json.dumps(redact_secrets(payload, self.secret_values), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path

    def _publish(self, message_type: str, payload: dict[str, Any], refs: list[str]) -> None:
        if self.message_bus is None:
            return
        self.message_bus.publish(
            "poc-repair",
            "validation",
            message_type,
            payload,
            artifact_refs=[ref for ref in refs if ref],
        )


class TrustedPoCAssembler:
    def assemble(
        self,
        *,
        original_poc: PoCArtifact,
        manifest: PoCRepairManifest,
        edits: list[PoCNormalizedEdit],
        attempt_dir: str | Path,
        attempt_index: int,
    ) -> PoCArtifact:
        attempt_dir = Path(attempt_dir)
        attempt_dir.mkdir(parents=True, exist_ok=True)
        source = Path(original_poc.script_path).read_text(encoding="utf-8")
        assembled = source
        slots = {slot.slot_id: slot for slot in manifest.editable_slots}
        for edit in edits:
            slot = slots.get(edit.slot_id)
            if slot is None or edit.op not in slot.operations:
                raise ValueError(f"unsupported edit {edit.op}:{edit.slot_id}")
            if edit.op == "add_import":
                statement = f"import {edit.module}" if not edit.name else f"from {edit.module} import {edit.name}"
                assembled = _insert_slot_line(assembled, slot, statement)
            elif edit.op == "replace_slot":
                assembled = _replace_slot_value(assembled, slot, edit.value or "")
            else:
                raise ValueError(f"unsupported edit operation: {edit.op}")
        normalized_payload = [item.to_dict() for item in edits]
        edit_hash = canonical_hash(normalized_payload)
        edit_path = immutable_path(attempt_dir / "normalized-edits.json")
        edit_path.write_text(
            json.dumps({"edit_hash": edit_hash, "edits": normalized_payload}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        script_path = immutable_path(attempt_dir / "poc.py")
        script_path.write_text(assembled, encoding="utf-8")
        script_hash = sha256_text(assembled)
        repaired = PoCArtifact(
            finding_id=original_poc.finding_id,
            vulnerability_class=original_poc.vulnerability_class,
            generator_id=original_poc.generator_id,
            script_path=str(script_path),
            command_argv=[sys.executable, str(script_path)],
            expected_signal=json.loads(json.dumps(original_poc.expected_signal)),
            safety_profile={
                **original_poc.safety_profile,
                "repair_applied": True,
                "repair_attempt_index": attempt_index,
            },
            source_refs=list(original_poc.source_refs),
            dataflow_trace_refs=list(original_poc.dataflow_trace_refs),
            target_file_refs=list(original_poc.target_file_refs),
            repair_manifest_ref=original_poc.repair_manifest_ref,
            repair_manifest_hash=original_poc.repair_manifest_hash,
            protected_node_hashes=dict(original_poc.protected_node_hashes),
            immutable_envelope_hash=original_poc.immutable_envelope_hash,
            immutable_envelope_ref=original_poc.immutable_envelope_ref,
            original_poc_ref=original_poc.metadata_path or original_poc.script_path,
            normalized_edit_ref=str(edit_path),
            normalized_edit_hash=edit_hash,
            script_hash=script_hash,
            attempt_index=attempt_index,
        )
        metadata_path = immutable_path(attempt_dir / "poc.json")
        repaired.metadata_path = str(metadata_path)
        metadata_path.write_text(json.dumps(repaired.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return repaired


class PoCSemanticIntegrityGate:
    def evaluate(
        self,
        *,
        original_poc: PoCArtifact,
        candidate_poc: PoCArtifact,
        manifest: PoCRepairManifest,
        attempt_index: int,
    ) -> PoCSemanticIntegrityDecision:
        rules: list[str] = []
        changed_ids: list[str] = []
        locations: list[dict[str, Any]] = []
        script = Path(candidate_poc.script_path).read_text(encoding="utf-8")
        script_hash = sha256_text(script)
        if manifest_hash(manifest) != manifest.manifest_hash:
            rules.append("semantic-manifest-hash-mismatch")
        if candidate_poc.immutable_envelope_hash != original_poc.immutable_envelope_hash:
            rules.append("semantic-execution-envelope-changed")
        if candidate_poc.expected_signal != original_poc.expected_signal:
            rules.append("semantic-expected-signal-changed")
        current = protected_nodes_from_script(script, manifest.editable_slots)
        expected_counts = Counter(item.ast_hash for item in manifest.protected_nodes)
        current_counts = Counter(item.ast_hash for item in current)
        missing_counts = expected_counts - current_counts
        extra_counts = current_counts - expected_counts
        if missing_counts:
            rules.append("semantic-protected-node-changed")
            for node in manifest.protected_nodes:
                if missing_counts[node.ast_hash] > 0:
                    changed_ids.append(node.node_id)
                    locations.append(node.source_location)
                    missing_counts[node.ast_hash] -= 1
        if extra_counts:
            rules.append("semantic-edit-outside-declared-slot")
        slot_text = "\n".join(_slot_contents(script, manifest.editable_slots))
        protected_literals = (
            set(manifest.expected_markers)
            | set(manifest.protected_result_filenames)
            | PROTECTED_MARKERS
            | {"sqli-result.json"}
        )
        if any(item and item in slot_text for item in protected_literals):
            rules.append("semantic-protected-evidence-emitter-in-slot")
        if any(name in slot_text for name in ("baseline_count", "attack_count", "marker_seen", "status = 'confirmed'")):
            rules.append("semantic-hard-coded-judge-measurement")
        allowed = not rules
        return PoCSemanticIntegrityDecision(
            finding_id=candidate_poc.finding_id,
            attempt_index=attempt_index,
            allowed=allowed,
            script_hash=script_hash,
            manifest_hash=manifest.manifest_hash,
            rule_ids=sorted(set(rules)),
            changed_protected_node_ids=sorted(set(changed_ids)),
            source_locations=locations,
            reason="Protected generator semantics are unchanged." if allowed else "Semantic integrity policy denied the script.",
        )


class PoCSafetyGate:
    def evaluate(
        self,
        *,
        poc: PoCArtifact,
        attempt_index: int,
        repaired: bool = False,
    ) -> PoCSafetyDecision:
        script = Path(poc.script_path).read_text(encoding="utf-8")
        script_hash = sha256_text(script)
        rules: list[str] = []
        locations: list[dict[str, Any]] = []
        try:
            tree = ast.parse(script)
        except SyntaxError as exc:
            return PoCSafetyDecision(
                finding_id=poc.finding_id,
                attempt_index=attempt_index,
                allowed=False,
                script_hash=script_hash,
                rule_ids=["safety-python-syntax-error"],
                source_locations=[{"line": exc.lineno or 0, "column": exc.offset or 0}],
                reason=str(exc),
                repaired=repaired,
            )
        for node in ast.walk(tree):
            rule = None
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".")[0] for alias in node.names}
                if roots & DENIED_IMPORT_ROOTS:
                    rule = "safety-forbidden-import"
                elif any(root not in SAFE_IMPORT_MODULES for root in roots):
                    rule = "safety-import-not-allowlisted"
            elif isinstance(node, ast.ImportFrom):
                root = str(node.module or "").split(".")[0]
                if root in DENIED_IMPORT_ROOTS:
                    rule = "safety-forbidden-import"
                elif root and root not in SAFE_IMPORT_MODULES:
                    rule = "safety-import-not-allowlisted"
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in DENIED_CALLS:
                    rule = "safety-process-or-dynamic-code"
                elif isinstance(node.func, ast.Call):
                    rule = "safety-opaque-dynamic-call"
                elif name in {"getattr", "setattr", "delattr", "globals", "locals", "vars"}:
                    rule = "safety-dynamic-reflection"
                elif name == "open" and _open_call_writes_unsafely(node):
                    rule = "safety-target-or-host-write"
                elif name in {"Path", "pathlib.Path", "PurePath", "pathlib.PurePath", "open", "os.open"} and _call_uses_host_absolute_path(node):
                    rule = "safety-host-absolute-path"
                elif name.endswith((".unlink", ".rmdir", ".chmod", ".rename", ".replace")):
                    rule = "safety-destructive-filesystem-call"
                elif name.endswith((".connect", ".urlopen", ".request", ".get", ".post")) and not name.startswith("sqlite3"):
                    rule = "safety-network-call"
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                lowered = value.lower()
                if re.search(r"https?://|ftp://", lowered):
                    rule = "safety-network-literal"
                elif "docker.sock" in lowered or "docker desktop" in lowered:
                    rule = "safety-docker-control"
                elif re.search(r"(?:^|\s)(?:pip|pip3|npm|apt|apk|yum)\s+install\b", lowered):
                    rule = "safety-dependency-install"
            if rule:
                rules.append(rule)
                locations.append(
                    {
                        "rule_id": rule,
                        "line": int(getattr(node, "lineno", 0) or 0),
                        "column": int(getattr(node, "col_offset", 0) or 0),
                    }
                )
        allowed = not rules
        return PoCSafetyDecision(
            finding_id=poc.finding_id,
            attempt_index=attempt_index,
            allowed=allowed,
            script_hash=script_hash,
            rule_ids=sorted(set(rules)) if rules else ["safety-python-ast-v1"],
            source_locations=locations,
            reason="Python PoC passed the constrained AST policy." if allowed else "Python PoC was denied by the constrained AST policy.",
            repaired=repaired,
        )


class PoCFailureClassifier:
    ENVIRONMENT_STATUSES = {
        "environment-unavailable",
        "image-unavailable",
        "docker-failed",
        "timed-out",
    }

    def classify(
        self,
        *,
        finding_id: str,
        attempt_index: int,
        stage: str,
        sandbox_result: SandboxRunResult | None = None,
        judge: Any | None = None,
        safety: PoCSafetyDecision | None = None,
        compatible_slot_ids: list[str] | None = None,
    ) -> PoCFailureClassification:
        slots = compatible_slot_ids or []
        refs: list[str] = []
        if safety and safety.metadata_path:
            refs.append(safety.metadata_path)
        if sandbox_result:
            refs.extend(
                ref
                for ref in [sandbox_result.metadata_path, sandbox_result.stdout_ref, sandbox_result.stderr_ref]
                if ref
            )
        if safety and not safety.allowed:
            return self._record(
                finding_id, attempt_index, PoCFailureClass.POLICY_DENIED, False,
                "PoC safety policy denied execution.", stage, refs, []
            )
        if sandbox_result and sandbox_result.status == "policy-denied":
            return self._record(
                finding_id, attempt_index, PoCFailureClass.POLICY_DENIED, False,
                sandbox_result.message or "Sandbox policy denied execution.", stage, refs, []
            )
        if sandbox_result and (sandbox_result.status in self.ENVIRONMENT_STATUSES or sandbox_result.timed_out):
            return self._record(
                finding_id, attempt_index, PoCFailureClass.ENVIRONMENT_ERROR, False,
                sandbox_result.message or "Sandbox environment could not complete execution.", stage, refs, []
            )
        if judge is not None and str(getattr(judge, "status", "")) == "rejected":
            refs.extend(getattr(judge, "evidence_refs", []) or [])
            return self._record(
                finding_id, attempt_index, PoCFailureClass.SEMANTIC_REJECTED, False,
                str(getattr(judge, "reason", "Deterministic Judge rejected the candidate.")), "judge", refs, []
            )
        diagnostic = ""
        if sandbox_result:
            diagnostic = "\n".join([sandbox_result.stderr_preview, sandbox_result.stdout_preview]).lower()
        harness_tokens = (
            "syntaxerror", "nameerror", "importerror", "modulenotfounderror", "filenotfounderror",
            "attributeerror", "typeerror", "fixture", "no such file or directory",
        )
        if sandbox_result and (sandbox_result.exit_code not in {None, 0}) and any(token in diagnostic for token in harness_tokens):
            import_slots = [slot for slot in slots if "import" in slot or slot == "imports"]
            setup_slots = [slot for slot in slots if "setup" in slot]
            import_failure = any(
                token in diagnostic
                for token in ("importerror", "modulenotfounderror", "name 'path' is not defined", "name 'os' is not defined")
            )
            eligible_slots = (import_slots if import_failure else setup_slots) or slots
            return self._record(
                finding_id, attempt_index, PoCFailureClass.HARNESS_ERROR, bool(eligible_slots),
                "PoC harness failed before Judge evidence was produced.", "runner", refs, eligible_slots
            )
        if judge is not None and str(getattr(judge, "status", "")) == "manual-required":
            setup_slots = [slot for slot in slots if "setup" in slot]
            return self._record(
                finding_id, attempt_index, PoCFailureClass.MISSING_EVIDENCE, bool(setup_slots),
                str(getattr(judge, "reason", "Judge evidence was missing.")), "judge", refs, setup_slots
            )
        return self._record(
            finding_id, attempt_index, PoCFailureClass.UNKNOWN, False,
            "Failure could not be proven repairable; classification failed closed.", stage, refs, []
        )

    @staticmethod
    def _record(
        finding_id: str,
        attempt_index: int,
        failure_class: PoCFailureClass,
        eligible: bool,
        reason: str,
        stage: str,
        refs: list[str],
        slots: list[str],
    ) -> PoCFailureClassification:
        return PoCFailureClassification(
            finding_id=finding_id,
            attempt_index=attempt_index,
            failure_class=failure_class,
            eligible=eligible,
            reason=reason,
            stage=stage,
            evidence_refs=_dedupe(refs),
            compatible_slot_ids=_dedupe(slots),
        )


def persist_gate_record(record: Any, path: str | Path) -> str:
    target = immutable_path(Path(path))
    record.metadata_path = str(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return str(target)


def build_target_manifest(root_path: str | Path, phase: str) -> TargetFileManifest:
    root = Path(root_path).resolve()
    files: dict[str, str] = {}
    excluded_parts = {".git", ".venv", "node_modules", "runs", "__pycache__"}
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if any(part in excluded_parts for part in relative.parts):
                continue
            try:
                files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                files[relative.as_posix()] = "<unreadable>"
    return TargetFileManifest(root_path=str(root), phase=phase, files=files)


def compare_target_manifests(
    before: TargetFileManifest, after: TargetFileManifest
) -> TargetIntegrityComparison:
    before_keys = set(before.files)
    after_keys = set(after.files)
    changed = sorted(path for path in before_keys & after_keys if before.files[path] != after.files[path])
    added = sorted(after_keys - before_keys)
    removed = sorted(before_keys - after_keys)
    return TargetIntegrityComparison(
        before_ref=before.metadata_path or before.id or "",
        after_ref=after.metadata_path or after.id or "",
        unchanged=not (changed or added or removed),
        changed_files=changed,
        added_files=added,
        removed_files=removed,
    )


def _persist_record(record: PoCRepairRecord, path: Path) -> None:
    persist_gate_record(record, path)


def _check_exact_keys(value: dict[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} has extra fields: {', '.join(extra)}")


def _bounded_string(value: Any, label: str, maximum: int, errors: list[str]) -> str:
    if not isinstance(value, str):
        errors.append(f"{label} must be a string")
        return ""
    text = value.strip()
    if not text:
        errors.append(f"{label} must be non-empty")
    if len(text) > maximum:
        errors.append(f"{label} exceeds {maximum} characters")
    return text


def _slot_line_ranges(script_text: str, slots: list[PoCEditableSlot]) -> list[tuple[int, int]]:
    lines = script_text.splitlines()
    ranges: list[tuple[int, int]] = []
    for slot in slots:
        start = next((index for index, line in enumerate(lines, 1) if line.strip() == slot.start_marker), 0)
        end = next((index for index, line in enumerate(lines, 1) if line.strip() == slot.end_marker), 0)
        if start and end and start < end:
            ranges.append((start + 1, end - 1))
    return ranges


def _inside_any_slot(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(slot_start <= start and end <= slot_end for slot_start, slot_end in ranges)


def _ast_hash(node: ast.AST) -> str:
    return sha256_text(ast.dump(node, annotate_fields=True, include_attributes=False))


def _protected_category(node: ast.AST) -> str:
    text = ast.unparse(node).lower()
    if any(marker.lower() in text for marker in PROTECTED_MARKERS):
        return "marker"
    if "sqli-result.json" in text or "write_text" in text:
        return "result-writer"
    if any(token in text for token in ("baseline_count", "attack_count", "marker_seen", "relative_to")):
        return "measurement"
    if any(token in text for token in ("cursor.execute", "_fetch_rows", "candidate =", "resolved =")):
        return "sink"
    if any(token in text for token in ("attack_payload", "_payload", "query")):
        return "payload"
    return "protected"


def _insert_slot_line(script: str, slot: PoCEditableSlot, statement: str) -> str:
    if statement in script.splitlines():
        return script
    lines = script.splitlines()
    end = next((index for index, line in enumerate(lines) if line.strip() == slot.end_marker), None)
    start = next((index for index, line in enumerate(lines) if line.strip() == slot.start_marker), None)
    if start is None or end is None or start >= end:
        raise ValueError(f"repair slot markers not found: {slot.slot_id}")
    lines.insert(end, statement)
    return "\n".join(lines)


def _replace_slot_value(script: str, slot: PoCEditableSlot, value: str) -> str:
    lines = script.splitlines()
    start = next((index for index, line in enumerate(lines) if line.strip() == slot.start_marker), None)
    end = next((index for index, line in enumerate(lines) if line.strip() == slot.end_marker), None)
    if start is None or end is None or start >= end:
        raise ValueError(f"repair slot markers not found: {slot.slot_id}")
    return "\n".join([*lines[: start + 1], *value.splitlines(), *lines[end:]])


def _slot_contents(script: str, slots: list[PoCEditableSlot]) -> list[str]:
    lines = script.splitlines()
    values: list[str] = []
    for slot in slots:
        start = next((index for index, line in enumerate(lines) if line.strip() == slot.start_marker), None)
        end = next((index for index, line in enumerate(lines) if line.strip() == slot.end_marker), None)
        if start is not None and end is not None and start < end:
            values.append("\n".join(lines[start + 1 : end]))
    return values


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _open_call_writes_unsafely(node: ast.Call) -> bool:
    mode = "r"
    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
        mode = node.args[1].value
    for keyword in node.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            mode = keyword.value.value
    if not any(flag in mode for flag in "wax+"):
        return False
    if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
        return True
    value = node.args[0].value
    return value.startswith(("/", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", value)) or ".." in Path(value).parts


def _call_uses_host_absolute_path(node: ast.Call) -> bool:
    if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
        return False
    value = node.args[0].value
    if value.startswith("/attempt"):
        return False
    return (
        value.startswith(("/", "\\\\"))
        or bool(re.match(r"^[A-Za-z]:[\\/]", value))
        or ".." in Path(value).parts
    )


def _bounded_read(path: Path, limit: int) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _grounded_source_snippets(
    finding: Finding,
    metadata: RepositoryMetadata,
    trace_refs: list[str],
) -> str:
    root = Path(metadata.root_path or ".").resolve()
    candidates: list[tuple[str, int]] = [(finding.location.path, finding.location.start_line)]
    for ref in trace_refs[:3]:
        try:
            trace = json.loads(Path(ref).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for key in ("source", "sink"):
            item = trace.get(key) or {}
            candidates.append((str(item.get("path") or ""), int(item.get("line") or 1)))
    snippets: list[str] = []
    seen: set[str] = set()
    for relative, line in candidates:
        if not relative:
            continue
        try:
            path = (root / relative).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                continue
        except (OSError, ValueError):
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(0, line - 6)
        end = min(len(lines), line + 5)
        numbered = "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))
        snippets.append(f"FILE {relative}\n{numbered}")
    return "\n\n".join(snippets)


def _dedupe(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "")
        if text and text not in result:
            result.append(text)
    return result


def _configured_secret_values(config: AuditConfig) -> list[str]:
    env_name = str(getattr(config.llm, "api_key_env", "") or "")
    value = os.environ.get(env_name) if env_name else None
    return [value] if value else []
