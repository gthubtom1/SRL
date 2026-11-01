"""Bounded, host-neutral diagnosis of supplied observations; never executes a target."""
from __future__ import annotations

import json

PLAYBOOK = "Tool/playbooks/risk-aware-analysis.md"
_ENUMS = {
    "process_role": {"target", "tool", "unknown"},
    "process_state": {"running", "paused", "exited", "crashed", "unknown"},
    "pause_reason": {"first_chance", "breakpoint", "manual", "unknown"},
    "request_phase": {"not_started", "paused_before_send", "sent_pending", "completed", "failed", "cancelled", "unknown"},
    "response_kind": {"business", "challenge", "login", "unknown"},
    "tool_selftest": {"passed_same_runtime", "passed_other_runtime", "failed", "not_run"},
    "business_event": {"none", "account_restricted", "device_binding", "environment_rejected", "rate_limited", "unknown"},
}
_BOOLS = {"business_verified", "capture_relevant", "child_observed"}


def diagnose(facts: dict) -> dict:
    """Return evidence questions, not a claim that caller-supplied facts are verified."""
    if not isinstance(facts, dict) or set(facts) - (set(_ENUMS) | _BOOLS | {"http_status"}):
        raise ValueError("facts must contain only documented observation fields")
    for key, value in facts.items():
        if key in _ENUMS and (not isinstance(value, str) or value not in _ENUMS[key]):
            raise ValueError("invalid observation enum: " + key)
        if key in _BOOLS and type(value) is not bool:
            raise ValueError("observation must be boolean: " + key)
    status = facts.get("http_status")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ValueError("http_status must be an integer in 100..599")
    observations, candidates, actions = [], [], []
    phase = facts.get("request_phase", "unknown")
    state = facts.get("process_state", "unknown")
    if state == "paused":
        observations.append("process_paused_not_proven_crashed")
        actions.append("inspect_pause_reason_and_thread_before_restart")
        if facts.get("pause_reason") == "first_chance":
            candidates.append("normal_exception_control_flow_or_fault_not_yet_classified")
            actions.append("inspect_this_exception_and_application_handler_not_ignore_all")
    if state in {"exited", "crashed"}:
        observations.append(facts.get("process_role", "unknown") + "_" + state)
        candidates += (["tool_or_plugin_fault", "external_termination_unknown"]
                       if facts.get("process_role") == "tool" else
                       ["dependency_or_instrumentation_fault", "local_detection", "normal_process_handoff", "remote_business_rejection"])
        actions.append("collect_exact_instance_exit_or_crash_and_last_event")
    if facts.get("child_observed"):
        actions.append("bind_business_child_by_image_pid_and_creation_identity")
    if facts.get("tool_selftest") in {"failed", "passed_other_runtime", "not_run"}:
        actions.append("calibrate_on_harmless_matching_platform_abi_and_runtime")
    if phase == "paused_before_send":
        observations.append("response_does_not_exist_yet")
        actions += ["inspect_request_only_without_waiting_for_response", "check_scope_before_resuming_execution"]
    elif phase == "sent_pending":
        observations.append("request_sent_result_pending")
        actions.append("bounded_wait_or_record_unknown_do_not_resend")
    elif phase == "failed":
        actions.append("establish_dispatch_stage_before_considering_retry")
    if facts.get("response_kind") == "challenge":
        observations.append("challenge_page_not_business_success")
        actions.append("preserve_session_and_evidence_do_not_refresh_loop")
    elif facts.get("response_kind") == "login":
        actions.append("inspect_session_expiry_and_existing_scope_before_reauthentication")
    if status in {401, 403}:
        actions.append("identify_response_source_and_business_code_not_assume_ban")
    event = facts.get("business_event", "none")
    pause_remote = status == 429 or event in {"account_restricted", "device_binding", "environment_rejected", "rate_limited"}
    if pause_remote:
        actions += ["pause_related_remote_attempts_and_record_evidence", "continue_unaffected_offline_work"]
    if facts.get("capture_relevant") is False:
        observations.append("capture_does_not_support_current_business_question")
        actions.append("correct_prior_claim_and_select_relevant_capture_boundary")
    if not actions:
        actions.append("read_existing_method_and_collect_smallest_discriminating_observation")
    return {
        "schema": "seep.runtime-diagnosis/1", "ok": True,
        "fact_status": "caller_supplied_not_independently_verified",
        "observations": observations, "candidate_causes": list(dict.fromkeys(candidates)),
        "cause_confirmed": False, "next_actions": list(dict.fromkeys(actions)),
        "pause_related_remote": pause_remote, "offline_work_allowed": True,
        "response_export_available": phase == "completed",
        "functionality_verified": False,
        "caller_reports_business_verified": facts.get("business_verified", False),
        "references": [PLAYBOOK], "coverage": "diagnostic_advice_not_process_or_network_control",
    }


def diagnose_json(value: str) -> dict:
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("facts_json must be at most 8192 characters")
    try:
        return diagnose(json.loads(value))
    except RecursionError:
        raise ValueError("observation nesting too deep") from None
