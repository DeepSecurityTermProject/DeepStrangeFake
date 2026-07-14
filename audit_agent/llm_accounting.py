from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .llm import LLMBudgetExceeded, LLMProviderError
from .models import LLMRequest, LLMResponse, stable_id, to_plain, utc_now
from .redaction import redact_secrets


EVENT_SCHEMA_VERSION = "llm-lifecycle-event.v1"
RECONCILIATION_SCHEMA_VERSION = "llm-accounting-reconciliation.v1"
EVENT_KINDS = {
    "request-started",
    "provider-dispatch-started",
    "provider-response-received",
    "provider-attempt-failed",
    "schema-valid",
    "schema-invalid",
    "policy-accepted",
    "policy-denied",
    "fallback-used",
    "budget-denied",
    "request-terminal",
}
TERMINAL_STATUSES = {
    "accepted",
    "fallback",
    "provider-error",
    "timeout",
    "budget-denied",
    "incomplete",
}
ACCOUNTING_SOURCES = {
    "lifecycle-ledger",
    "compatibility-observer",
    "legacy-artifact-scan",
    "disabled-zero",
    "unknown",
}


@dataclass
class LLMRequestGroupRecord:
    request_group_id: str
    run_id: str
    request_id: str
    role: str
    accounting_source: str
    provider_attempt_ids: list[str] = field(default_factory=list)
    terminal_status: str | None = None
    schema_version: str = "llm-request-group.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "llm-request-group.v1":
            raise ValueError(f"unsupported request-group schema: {self.schema_version}")
        if not self.request_group_id or not self.run_id or not self.request_id or not self.role:
            raise ValueError("request-group identity is required")
        if self.accounting_source not in ACCOUNTING_SOURCES:
            raise ValueError(f"unsupported accounting source: {self.accounting_source}")
        if self.terminal_status is not None and self.terminal_status not in TERMINAL_STATUSES:
            raise ValueError(f"unsupported terminal status: {self.terminal_status}")
        if len(self.provider_attempt_ids) != len(set(self.provider_attempt_ids)):
            raise ValueError("duplicate provider attempt ID")

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class ProviderAttemptRecord:
    provider_attempt_id: str
    request_group_id: str
    attempt_index: int
    outcome: str = "dispatched"
    usage: dict[str, int] | None = None
    schema_version: str = "llm-provider-attempt.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "llm-provider-attempt.v1":
            raise ValueError(f"unsupported provider-attempt schema: {self.schema_version}")
        if not self.provider_attempt_id or not self.request_group_id:
            raise ValueError("provider-attempt identity is required")
        if isinstance(self.attempt_index, bool) or not isinstance(self.attempt_index, int) or self.attempt_index < 1:
            raise ValueError("provider attempt index must be positive")
        if self.outcome not in {"dispatched", "response", "failed", "timeout"}:
            raise ValueError(f"unsupported provider attempt outcome: {self.outcome}")

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class LifecycleEvent:
    event_id: str
    request_group_id: str
    sequence: int
    kind: str
    role: str
    provider: str | None = None
    model: str | None = None
    provider_attempt_id: str | None = None
    terminal_status: str | None = None
    accounting_source: str = "lifecycle-ledger"
    prompt_ref: str | None = None
    response_ref: str | None = None
    error_ref: str | None = None
    decision_refs: list[str] = field(default_factory=list)
    usage: dict[str, int] | None = None
    details: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EVENT_SCHEMA_VERSION:
            raise ValueError(f"unsupported lifecycle schema: {self.schema_version}")
        if not self.event_id or not self.request_group_id or not self.role:
            raise ValueError("lifecycle identity and role are required")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 1:
            raise ValueError("lifecycle sequence must be a positive integer")
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"unsupported lifecycle event kind: {self.kind}")
        if self.accounting_source not in ACCOUNTING_SOURCES:
            raise ValueError(f"unsupported accounting source: {self.accounting_source}")
        if self.kind in {
            "provider-dispatch-started",
            "provider-response-received",
            "provider-attempt-failed",
        } and not self.provider_attempt_id:
            raise ValueError(f"{self.kind} requires provider_attempt_id")
        if self.kind == "provider-response-received" and not self.response_ref:
            raise ValueError("provider-response-received requires response_ref")
        if self.kind == "request-terminal":
            if self.terminal_status not in TERMINAL_STATUSES:
                raise ValueError("request-terminal requires a supported terminal status")
        elif self.terminal_status is not None:
            raise ValueError("terminal_status is valid only on request-terminal")

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LifecycleEvent":
        if not isinstance(payload, dict):
            raise ValueError("lifecycle event must be an object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"unknown lifecycle fields: {sorted(unknown)}")
        return cls(**payload)


@dataclass(frozen=True)
class ReconciliationGap:
    gap_id: str
    field: str
    reason: str
    request_group_id: str | None = None
    provider_attempt_id: str | None = None
    ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)


@dataclass
class LLMAccountingReconciliation:
    ledger_present: bool
    accounting_source: str
    complete: bool
    request_counts_complete: bool
    provider_attempt_counts_complete: bool
    token_counts_complete: bool
    total_request_groups: int | None
    llm_requests: int | None
    provider_attempts: int | None
    retries: int | None
    pre_dispatch_denials: int | None
    llm_tokens: int | None
    terminal_status_counts: dict[str, int] = field(default_factory=dict)
    gaps: list[ReconciliationGap] = field(default_factory=list)
    contributing_refs: list[str] = field(default_factory=list)
    request_groups: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = RECONCILIATION_SCHEMA_VERSION

    @property
    def gap_ids(self) -> list[str]:
        return [item.gap_id for item in self.gaps]

    def to_dict(self) -> dict[str, Any]:
        payload = to_plain(self)
        payload["gap_ids"] = self.gap_ids
        return payload


class LifecycleLedger:
    def __init__(
        self,
        run_dir: str | Path,
        run_id: str,
        *,
        secret_values: list[str] | None = None,
        event_sink: Callable[[LifecycleEvent, str], None] | None = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.root = self.run_dir / "llm_attempts"
        self.run_id = run_id
        self.secret_values = [item for item in (secret_values or []) if item]
        self.event_sink = event_sink

    def request_group_id(self, request: LLMRequest, invocation_index: int = 1) -> str:
        if isinstance(invocation_index, bool) or not isinstance(invocation_index, int) or invocation_index < 1:
            raise ValueError("invocation index must be positive")
        return stable_id(
            "LLMRG",
            self.run_id,
            invocation_index,
            request.role,
            request.provider,
            request.model,
            request.created_at,
        )

    def provider_attempt_id(self, request_group_id: str, attempt_index: int) -> str:
        return stable_id("LLMPA", request_group_id, attempt_index)

    def event_id(self, request_group_id: str, sequence: int, kind: str) -> str:
        return stable_id("LLMEV", request_group_id, sequence, kind)

    def write_event(self, event: LifecycleEvent) -> str:
        group_root = self.root / event.request_group_id
        group_root.mkdir(parents=True, exist_ok=True)
        path = group_root / f"{event.sequence:04d}-{event.event_id}.json"
        payload = redact_secrets(event.to_dict(), self.secret_values)
        serialized = json.dumps(payload, ensure_ascii=False, indent=2)
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(serialized)
        except FileExistsError:
            raise FileExistsError(f"lifecycle event collision: {event.event_id}") from None
        if self.event_sink:
            self.event_sink(LifecycleEvent.from_dict(payload), str(path))
        return str(path)

    def write_json(self, category: str, name: str, payload: dict[str, Any]) -> str:
        root = self.run_dir / category
        root.mkdir(parents=True, exist_ok=True)
        path = root / name
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(redact_secrets(payload, self.secret_values), handle, ensure_ascii=False, indent=2)
        except FileExistsError:
            raise FileExistsError(f"immutable accounting artifact collision: {path}") from None
        return str(path)


@dataclass
class LLMInvocationReceipt:
    request_group_id: str
    request: LLMRequest
    role: str
    prompt_ref: str | None = None
    provider_attempt_ids: list[str] = field(default_factory=list)
    response: LLMResponse | None = None
    response_ref: str | None = None
    error_ref: str | None = None
    schema_ref: str | None = None
    policy_ref: str | None = None
    fallback_ref: str | None = None
    event_refs: list[str] = field(default_factory=list)
    terminal_status: str | None = None
    terminal_ref: str | None = None
    accounting_source: str = "lifecycle-ledger"
    _sequence: int = 0


class _AttemptObserver:
    def __init__(self, gateway: "AuditedLLMGateway", receipt: LLMInvocationReceipt) -> None:
        self.gateway = gateway
        self.receipt = receipt
        self.successful_attempt_id: str | None = None

    def dispatch_started(self, details: dict[str, Any] | None = None) -> str:
        attempt_id = self.gateway._start_attempt(self.receipt, details or {})
        return attempt_id

    def attempt_failed(self, attempt_id: str, details: dict[str, Any] | None = None) -> None:
        self.gateway._event(
            self.receipt,
            "provider-attempt-failed",
            provider_attempt_id=attempt_id,
            details=details or {},
        )

    def attempt_response(self, attempt_id: str, response: LLMResponse) -> None:
        self.successful_attempt_id = attempt_id


class AuditedLLMGateway:
    def __init__(
        self,
        client: Any,
        ledger: LifecycleLedger,
        *,
        request_budget: int,
        token_budget: int,
        response_writer: Callable[[LLMRequest, LLMResponse], str] | None = None,
        accounting_state: dict[str, Any] | None = None,
    ) -> None:
        self.client = client
        self.ledger = ledger
        self.request_budget = max(0, int(request_budget))
        self.token_budget = max(0, int(token_budget))
        self.response_writer = response_writer or self._default_response_writer
        self.accounting_state = accounting_state if accounting_state is not None else {}
        self.requests_used = int(self.accounting_state.get("requests_used", 0) or 0)
        self.tokens_used = int(self.accounting_state.get("tokens_used", 0) or 0)
        self._receipts: dict[str, LLMInvocationReceipt] = {}
        self._response_receipts: dict[str, LLMInvocationReceipt] = {}
        self._invocation_count = 0

    def complete(self, request: LLMRequest) -> LLMResponse:
        return self.invoke(request).response  # type: ignore[return-value]

    def receipt_for(self, request_or_id: LLMRequest | str) -> LLMInvocationReceipt | None:
        request_id = request_or_id.id if isinstance(request_or_id, LLMRequest) else request_or_id
        return self._receipts.get(str(request_id or ""))

    def receipt_for_response(self, response_id: str) -> LLMInvocationReceipt | None:
        return self._response_receipts.get(str(response_id or ""))

    def invoke(self, request: LLMRequest, prompt_ref: str | None = None) -> LLMInvocationReceipt:
        self._invocation_count += 1
        group_id = self.ledger.request_group_id(request, self._invocation_count)
        receipt = LLMInvocationReceipt(group_id, request, request.role, prompt_ref=prompt_ref)
        self._receipts[str(request.id or group_id)] = receipt
        self._event(
            receipt,
            "request-started",
            prompt_ref=prompt_ref,
            details={"request_id": request.id},
        )
        if self.requests_used >= self.request_budget:
            self._event(receipt, "budget-denied", details={"phase": "pre-dispatch", "budget": "requests"})
            self.terminalize(receipt, "budget-denied")
            error = LLMBudgetExceeded("LLM request budget exhausted")
            error.receipt = receipt  # type: ignore[attr-defined]
            raise error
        if self.tokens_used >= self.token_budget:
            self._event(receipt, "budget-denied", details={"phase": "pre-dispatch", "budget": "tokens"})
            self.terminalize(receipt, "budget-denied")
            error = LLMBudgetExceeded("LLM token budget exhausted")
            error.receipt = receipt  # type: ignore[attr-defined]
            raise error

        observer = _AttemptObserver(self, receipt)
        try:
            if hasattr(self.client, "complete_with_attempt_observer"):
                response = self.client.complete_with_attempt_observer(request, observer)
                receipt.accounting_source = "lifecycle-ledger"
            else:
                receipt.accounting_source = "compatibility-observer"
                attempt_id = observer.dispatch_started({"visibility": "one-observable-attempt"})
                try:
                    response = self.client.complete(request)
                except Exception as exc:
                    observer.attempt_failed(attempt_id, _safe_error_details(exc))
                    raise
                observer.attempt_response(attempt_id, response)
        except Exception as exc:
            error_ref = self.ledger.write_json(
                "llm_errors",
                f"{group_id}.json",
                {
                    "schema_version": "llm-provider-error.v1",
                    "request_group_id": group_id,
                    "provider_attempt_ids": receipt.provider_attempt_ids,
                    **_safe_error_details(exc),
                },
            )
            receipt.error_ref = error_ref
            status = "timeout" if _is_timeout(exc) else "provider-error"
            self.terminalize(receipt, status, error_ref=error_ref)
            raise

        attempt_id = observer.successful_attempt_id
        if attempt_id is None:
            if not receipt.provider_attempt_ids:
                attempt_id = observer.dispatch_started({"visibility": "client-returned-without-observer"})
            else:
                attempt_id = receipt.provider_attempt_ids[-1]
        response_ref = self.response_writer(request, response)
        receipt.response = response
        receipt.response_ref = response_ref
        if response.id:
            self._response_receipts[response.id] = receipt
        usage = _trustworthy_usage(response.usage)
        self._event(
            receipt,
            "provider-response-received",
            provider_attempt_id=attempt_id,
            response_ref=response_ref,
            usage=usage,
            details={"response_id": response.id, "finish_reason": response.finish_reason},
        )
        total = usage.get("total_tokens") if usage else None
        if total is not None:
            self.tokens_used += total
            self._sync_state()
            if self.tokens_used > self.token_budget:
                self._event(receipt, "budget-denied", details={"phase": "post-response", "budget": "tokens"})
                self.terminalize(receipt, "budget-denied")
                error = LLMBudgetExceeded("LLM response exceeded token budget")
                error.receipt = receipt  # type: ignore[attr-defined]
                raise error
        return receipt

    def record_schema(
        self,
        receipt: LLMInvocationReceipt,
        *,
        valid: bool,
        errors: list[str] | None = None,
    ) -> str:
        ref = self._event(
            receipt,
            "schema-valid" if valid else "schema-invalid",
            details={"errors": list(errors or [])},
        )
        receipt.schema_ref = ref
        return ref

    def record_policy(
        self,
        receipt: LLMInvocationReceipt,
        *,
        accepted: bool,
        reasons: list[str] | None = None,
    ) -> str:
        ref = self._event(
            receipt,
            "policy-accepted" if accepted else "policy-denied",
            details={"reasons": list(reasons or [])},
        )
        receipt.policy_ref = ref
        return ref

    def record_fallback(self, receipt: LLMInvocationReceipt, reason: str, refs: list[str] | None = None) -> str:
        ref = self._event(receipt, "fallback-used", details={"reason": reason}, decision_refs=refs or [])
        receipt.fallback_ref = ref
        return ref

    def terminalize(
        self,
        receipt: LLMInvocationReceipt,
        status: str,
        *,
        decision_refs: list[str] | None = None,
        error_ref: str | None = None,
    ) -> str:
        if status not in TERMINAL_STATUSES:
            raise ValueError(f"unsupported LLM terminal status: {status}")
        if receipt.terminal_status:
            if receipt.terminal_status != status:
                raise ValueError("contradictory LLM terminal outcome")
            return receipt.terminal_ref or ""
        ref = self._event(
            receipt,
            "request-terminal",
            terminal_status=status,
            decision_refs=decision_refs or [],
            error_ref=error_ref,
        )
        receipt.terminal_status = status
        receipt.terminal_ref = ref
        return ref

    def _start_attempt(self, receipt: LLMInvocationReceipt, details: dict[str, Any]) -> str:
        attempt_id = self.ledger.provider_attempt_id(receipt.request_group_id, len(receipt.provider_attempt_ids) + 1)
        if attempt_id in receipt.provider_attempt_ids:
            raise ValueError(f"duplicate provider attempt ID: {attempt_id}")
        receipt.provider_attempt_ids.append(attempt_id)
        if len(receipt.provider_attempt_ids) == 1:
            self.requests_used += 1
            self._sync_state()
        self._event(
            receipt,
            "provider-dispatch-started",
            provider_attempt_id=attempt_id,
            details=details,
        )
        return attempt_id

    def _event(
        self,
        receipt: LLMInvocationReceipt,
        kind: str,
        *,
        provider_attempt_id: str | None = None,
        terminal_status: str | None = None,
        prompt_ref: str | None = None,
        response_ref: str | None = None,
        error_ref: str | None = None,
        decision_refs: list[str] | None = None,
        usage: dict[str, int] | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        receipt._sequence += 1
        event = LifecycleEvent(
            event_id=self.ledger.event_id(receipt.request_group_id, receipt._sequence, kind),
            request_group_id=receipt.request_group_id,
            sequence=receipt._sequence,
            kind=kind,
            role=receipt.role,
            provider=receipt.request.provider,
            model=receipt.request.model,
            provider_attempt_id=provider_attempt_id,
            terminal_status=terminal_status,
            accounting_source=receipt.accounting_source,
            prompt_ref=prompt_ref,
            response_ref=response_ref,
            error_ref=error_ref,
            decision_refs=list(decision_refs or []),
            usage=usage,
            details=details or {},
        )
        ref = self.ledger.write_event(event)
        receipt.event_refs.append(ref)
        return ref

    def _default_response_writer(self, request: LLMRequest, response: LLMResponse) -> str:
        return self.ledger.write_json(
            "llm",
            f"{request.role}-{response.id}.json",
            {"request": request.to_dict(), "response": response.to_dict()},
        )

    def _sync_state(self) -> None:
        self.accounting_state.update(
            {"requests_used": self.requests_used, "tokens_used": self.tokens_used}
        )


def reconcile_llm_lifecycle(
    run_dir: str | Path,
    *,
    llm_enabled: bool | None = None,
    budget_counters: dict[str, int] | None = None,
) -> LLMAccountingReconciliation:
    run_path = Path(run_dir)
    ledger_root = run_path / "llm_attempts"
    if not ledger_root.exists():
        return _legacy_or_disabled_reconciliation(run_path, llm_enabled)

    gaps: list[ReconciliationGap] = []
    events: list[tuple[LifecycleEvent, str]] = []
    event_ids: set[str] = set()
    for path in sorted(ledger_root.glob("*/*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            event = LifecycleEvent.from_dict(payload)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            gaps.append(_gap("ledger", "corrupt-event", ref=str(path), detail=type(exc).__name__))
            continue
        if event.event_id in event_ids:
            gaps.append(_gap("provider_attempts", "duplicate-event-id", event.request_group_id, ref=str(path)))
            continue
        event_ids.add(event.event_id)
        events.append((event, str(path)))

    groups: dict[str, list[tuple[LifecycleEvent, str]]] = {}
    for item in events:
        groups.setdefault(item[0].request_group_id, []).append(item)
    dispatched_groups = 0
    provider_attempts = 0
    pre_denials = 0
    tokens = 0
    tokens_complete = True
    attempts_complete = True
    request_complete = not any(item.field == "ledger" for item in gaps)
    terminal_counts: dict[str, int] = {}
    request_summaries = []
    contributing_refs = [ref for _, ref in events]
    event_sources = {event.accounting_source for event, _ in events}

    for group_id in sorted(groups):
        items = sorted(groups[group_id], key=lambda item: (item[0].sequence, item[0].event_id))
        sequences = [item[0].sequence for item in items]
        if not items or items[0][0].kind != "request-started":
            gaps.append(_gap("llm_requests", "missing-request-started", group_id))
            request_complete = False
        if sum(1 for event, _ in items if event.kind == "request-started") != 1:
            gaps.append(_gap("ledger", "invalid-request-start-count", group_id))
            request_complete = False
        if len(sequences) != len(set(sequences)) or sequences != list(range(1, max(sequences, default=0) + 1)):
            gaps.append(_gap("ledger", "invalid-event-sequence", group_id))
            request_complete = False
        terminals = [event for event, _ in items if event.kind == "request-terminal"]
        if len(terminals) != 1:
            reason = "missing-terminal" if not terminals else "duplicate-terminal"
            gaps.append(_gap("terminal_status", reason, group_id))
        elif terminals[0].terminal_status:
            value = terminals[0].terminal_status
            terminal_counts[value] = terminal_counts.get(value, 0) + 1

        dispatched_attempts: set[str] = set()
        completed_attempts: set[str] = set()
        response_seen = False
        schema_seen = False
        terminal_seen = False
        for event, _ in items:
            illegal = False
            if terminal_seen:
                illegal = True
            elif event.kind == "provider-dispatch-started":
                attempt_id = str(event.provider_attempt_id)
                if attempt_id in dispatched_attempts:
                    illegal = True
                dispatched_attempts.add(attempt_id)
            elif event.kind in {"provider-response-received", "provider-attempt-failed"}:
                attempt_id = str(event.provider_attempt_id)
                if attempt_id not in dispatched_attempts or attempt_id in completed_attempts:
                    illegal = True
                completed_attempts.add(attempt_id)
                if event.kind == "provider-response-received":
                    response_seen = True
            elif event.kind in {"schema-valid", "schema-invalid"}:
                if not response_seen:
                    illegal = True
                schema_seen = True
            elif event.kind in {"policy-accepted", "policy-denied"} and not schema_seen:
                illegal = True
            elif event.kind == "request-terminal":
                terminal_seen = True
            if illegal:
                gaps.append(
                    _gap(
                        "ledger",
                        "illegal-transition",
                        group_id,
                        event.provider_attempt_id,
                        event.event_id,
                    )
                )
                request_complete = False

        dispatches = [event for event, _ in items if event.kind == "provider-dispatch-started"]
        attempt_ids = [str(item.provider_attempt_id) for item in dispatches]
        if len(attempt_ids) != len(set(attempt_ids)):
            gaps.append(_gap("provider_attempts", "duplicate-provider-attempt", group_id))
            attempts_complete = False
        if dispatches:
            dispatched_groups += 1
        provider_attempts += len(set(attempt_ids))
        budget_events = [event for event, _ in items if event.kind == "budget-denied"]
        if not dispatches and any(item.details.get("phase") == "pre-dispatch" for item in budget_events):
            pre_denials += 1

        response_events = [event for event, _ in items if event.kind == "provider-response-received"]
        request_started = next(
            (event for event, _ in items if event.kind == "request-started"),
            None,
        )
        response_usage_by_event: dict[str, dict[str, int] | None] = {}
        invalid_response_events: set[str] = set()
        correlated_artifact_refs: set[str] = set()
        for event, _ in items:
            for ref in [event.prompt_ref, event.error_ref, *event.decision_refs]:
                if not ref:
                    continue
                correlated_artifact_refs.add(str(ref))
                if _looks_like_artifact_ref(str(ref)) and not Path(ref).is_file():
                    field = "ledger"
                    gaps.append(
                        _gap(
                            field,
                            "missing-correlated-ref",
                            group_id,
                            event.provider_attempt_id,
                            str(ref),
                        )
                    )
        responses_by_attempt: dict[str, list[LifecycleEvent]] = {}
        for event in response_events:
            responses_by_attempt.setdefault(str(event.provider_attempt_id), []).append(event)
            if event.response_ref:
                contributing_refs.append(event.response_ref)
                if not Path(event.response_ref).is_file():
                    gaps.append(
                        _gap(
                            "llm_tokens",
                            "missing-response-ref",
                            group_id,
                            event.provider_attempt_id,
                            event.response_ref,
                        )
                    )
                    tokens_complete = False
                    invalid_response_events.add(event.event_id)
                else:
                    artifact_usage, artifact_gap = _validate_response_artifact(
                        event,
                        request_started,
                    )
                    if artifact_gap:
                        gaps.append(
                            _gap(
                                "llm_tokens",
                                artifact_gap,
                                group_id,
                                event.provider_attempt_id,
                                event.response_ref,
                            )
                        )
                        tokens_complete = False
                        invalid_response_events.add(event.event_id)
                    else:
                        response_usage_by_event[event.event_id] = artifact_usage
        for attempt_id in set(attempt_ids):
            attempt_responses = responses_by_attempt.get(attempt_id, [])
            if len(attempt_responses) > 1:
                gaps.append(_gap("llm_tokens", "duplicate-response", group_id, attempt_id))
                tokens_complete = False
                continue
            if not attempt_responses:
                gaps.append(_gap("llm_tokens", "usage-unknown", group_id, attempt_id))
                tokens_complete = False
                continue
            response_event = attempt_responses[0]
            if response_event.event_id in invalid_response_events:
                continue
            usage = response_usage_by_event.get(response_event.event_id)
            total = usage.get("total_tokens") if isinstance(usage, dict) else None
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                gaps.append(_gap("llm_tokens", "usage-unknown", group_id, attempt_id))
                tokens_complete = False
            else:
                tokens += total
        request_summaries.append(
            {
                "request_group_id": group_id,
                "role": items[0][0].role if items else "unknown",
                "provider": items[0][0].provider if items else None,
                "model": items[0][0].model if items else None,
                "provider_attempt_ids": sorted(set(attempt_ids)),
                "terminal_status": terminals[0].terminal_status if len(terminals) == 1 else "incomplete",
                "schema_status": next(
                    (
                        "valid" if event.kind == "schema-valid" else "invalid"
                        for event, _ in reversed(items)
                        if event.kind in {"schema-valid", "schema-invalid"}
                    ),
                    None,
                ),
                "policy_status": next(
                    (
                        "accepted" if event.kind == "policy-accepted" else "denied"
                        for event, _ in reversed(items)
                        if event.kind in {"policy-accepted", "policy-denied"}
                    ),
                    None,
                ),
                "fallback_reason": next(
                    (
                        str(event.details.get("reason") or "fallback")
                        for event, _ in reversed(items)
                        if event.kind == "fallback-used"
                    ),
                    None,
                ),
                "event_refs": [ref for _, ref in items],
                "last_event": items[-1][0].kind if items else None,
                "last_event_ref": items[-1][1] if items else None,
            }
        )

    correlated = {
        str(ref)
        for event, _ in events
        for ref in [event.prompt_ref, event.response_ref, event.error_ref, *event.decision_refs]
        if ref
    }
    for path in sorted((run_path / "llm").glob("*.json")) if (run_path / "llm").exists() else []:
        if str(path) not in correlated:
            gaps.append(_gap("ledger", "uncorrelated-llm-artifact", ref=str(path)))
            request_complete = False
    for path in sorted((run_path / "llm_errors").glob("*.json")) if (run_path / "llm_errors").exists() else []:
        if str(path) not in correlated:
            gaps.append(_gap("ledger", "uncorrelated-llm-error", ref=str(path)))
            request_complete = False

    if budget_counters is not None:
        expected_requests = budget_counters.get("requests_used")
        expected_tokens = budget_counters.get("tokens_used")
        if expected_requests is not None and int(expected_requests) != dispatched_groups:
            gaps.append(_gap("llm_requests", "budget-counter-mismatch"))
            request_complete = False
        if tokens_complete and expected_tokens is not None and int(expected_tokens) != tokens:
            gaps.append(_gap("llm_tokens", "budget-counter-mismatch"))
            tokens_complete = False

    complete = request_complete and attempts_complete and tokens_complete and not any(
        item.field in {"ledger", "terminal_status"} for item in gaps
    )
    return LLMAccountingReconciliation(
        ledger_present=True,
        accounting_source=(
            "compatibility-observer"
            if "compatibility-observer" in event_sources
            else "lifecycle-ledger"
        ),
        complete=complete,
        request_counts_complete=request_complete,
        provider_attempt_counts_complete=attempts_complete,
        token_counts_complete=tokens_complete,
        total_request_groups=len(groups),
        llm_requests=dispatched_groups if request_complete else None,
        provider_attempts=provider_attempts if attempts_complete else None,
        retries=max(0, provider_attempts - dispatched_groups) if attempts_complete and request_complete else None,
        pre_dispatch_denials=pre_denials if request_complete else None,
        llm_tokens=tokens if tokens_complete else None,
        terminal_status_counts=dict(sorted(terminal_counts.items())),
        gaps=sorted(gaps, key=lambda item: item.gap_id),
        contributing_refs=list(dict.fromkeys(contributing_refs)),
        request_groups=request_summaries,
    )


def replay_llm_lifecycle(
    run_dir: str | Path,
    *,
    llm_enabled: bool | None = None,
) -> dict[str, Any]:
    return reconcile_llm_lifecycle(run_dir, llm_enabled=llm_enabled).to_dict()


def _legacy_or_disabled_reconciliation(
    run_path: Path,
    llm_enabled: bool | None,
) -> LLMAccountingReconciliation:
    if llm_enabled is False:
        return LLMAccountingReconciliation(
            ledger_present=False,
            accounting_source="disabled-zero",
            complete=True,
            request_counts_complete=True,
            provider_attempt_counts_complete=True,
            token_counts_complete=True,
            total_request_groups=0,
            llm_requests=0,
            provider_attempts=0,
            retries=0,
            pre_dispatch_denials=0,
            llm_tokens=0,
        )
    llm_root = run_path / "llm"
    files = sorted(llm_root.glob("*.json")) if llm_root.exists() else []
    requests = 0
    tokens = 0
    refs = []
    gaps = [
        _gap("ledger", "legacy-accounting-unavailable"),
        _gap("llm_requests", "legacy-request-lifecycle-unavailable"),
        _gap("llm_tokens", "legacy-token-accounting-unavailable"),
    ]
    tokens_complete = bool(files)
    for path in files:
        refs.append(str(path))
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            usage = (payload.get("response") or {}).get("usage") or payload.get("usage")
            total = usage.get("total_tokens") if isinstance(usage, dict) else None
            if not isinstance(total, int) or isinstance(total, bool):
                tokens_complete = False
                continue
            requests += 1
            tokens += total
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            tokens_complete = False
    return LLMAccountingReconciliation(
        ledger_present=False,
        accounting_source="legacy-artifact-scan" if files else "unknown",
        complete=False,
        request_counts_complete=False,
        provider_attempt_counts_complete=False,
        token_counts_complete=False,
        total_request_groups=None,
        llm_requests=requests if files else None,
        provider_attempts=None,
        retries=None,
        pre_dispatch_denials=None,
        llm_tokens=tokens if files and tokens_complete else None,
        gaps=gaps,
        contributing_refs=refs,
    )


def _gap(
    field: str,
    reason: str,
    request_group_id: str | None = None,
    provider_attempt_id: str | None = None,
    ref: str | None = None,
    *,
    detail: str | None = None,
) -> ReconciliationGap:
    normalized_ref = Path(ref).name if ref else None
    gap_id = stable_id(
        "LLMGAP",
        field,
        reason,
        request_group_id,
        provider_attempt_id,
        normalized_ref,
        detail,
    )
    return ReconciliationGap(gap_id, field, reason, request_group_id, provider_attempt_id, ref)


def _trustworthy_usage(usage: Any) -> dict[str, int] | None:
    if not isinstance(usage, dict):
        return None
    total = usage.get("total_tokens")
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if total is None and isinstance(prompt, int) and not isinstance(prompt, bool) and isinstance(completion, int) and not isinstance(completion, bool):
        total = prompt + completion
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None
    result = {"total_tokens": total}
    if isinstance(prompt, int) and not isinstance(prompt, bool) and prompt >= 0:
        result["prompt_tokens"] = prompt
    if isinstance(completion, int) and not isinstance(completion, bool) and completion >= 0:
        result["completion_tokens"] = completion
    return result


def _validate_response_artifact(
    event: LifecycleEvent,
    request_started: LifecycleEvent | None,
) -> tuple[dict[str, int] | None, str | None]:
    try:
        payload = json.loads(Path(str(event.response_ref)).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None, "corrupt-response-artifact"
    if not isinstance(payload, dict):
        return None, "corrupt-response-artifact"
    request_payload = payload.get("request")
    response_payload = payload.get("response")
    if not isinstance(request_payload, dict) or not isinstance(response_payload, dict):
        return None, "corrupt-response-artifact"

    request_id = request_payload.get("id")
    response_request_id = response_payload.get("request_id")
    expected_request_id = (
        request_started.details.get("request_id")
        if request_started and isinstance(request_started.details, dict)
        else None
    )
    if (
        not isinstance(request_id, str)
        or not request_id
        or response_request_id != request_id
        or (expected_request_id is not None and request_id != expected_request_id)
    ):
        return None, "response-request-id-mismatch"

    expected_response_id = event.details.get("response_id")
    response_id = response_payload.get("id")
    if (
        not isinstance(expected_response_id, str)
        or not expected_response_id
        or response_id != expected_response_id
    ):
        return None, "response-id-mismatch"

    if (
        request_payload.get("role") != event.role
        or request_payload.get("provider") != event.provider
        or request_payload.get("model") != event.model
        or response_payload.get("provider") != event.provider
    ):
        return None, "response-metadata-mismatch"

    artifact_usage = _trustworthy_usage(response_payload.get("usage"))
    event_usage = _trustworthy_usage(event.usage)
    if artifact_usage != event_usage:
        return None, "response-usage-mismatch"
    return artifact_usage, None


def _safe_error_details(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, LLMProviderError):
        return {
            "error_type": exc.error_type,
            "provider": exc.provider,
            "model": exc.model,
            "status_code": exc.status_code,
            "diagnostic": exc.diagnostic,
        }
    return {"error_type": "timeout" if _is_timeout(exc) else type(exc).__name__, "diagnostic": str(exc)}


def _is_timeout(exc: Exception) -> bool:
    return isinstance(exc, TimeoutError) or (
        isinstance(exc, LLMProviderError) and exc.error_type == "timeout"
    )


def _looks_like_artifact_ref(value: str) -> bool:
    return "/" in value or "\\" in value or Path(value).suffix.lower() in {".json", ".jsonl"}
