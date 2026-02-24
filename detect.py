"""
Zapier Insights — Detection Zap Code Step.

Self-contained Python file for Zapier's "Code by Zapier" step.
Combines detection engine, health scoring, and Slack formatting.

Data source: Fetches CSV files from a GitHub repo via raw URLs.
Input: input_data with optional repo_url override.
Output: output dict with structured insights JSON + Slack message text.

No LLM. No ML. Deterministic detection only.
"""

import csv
import io
import json
import re
import requests
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from statistics import median

# --- Window constants ---
BASELINE_WINDOW_DAYS = 7       # trailing, excluding recent window
RECENT_WINDOW_HOURS = 48       # current observation period
BUCKET_HOURS = 6               # rolling bucket size for degradation onset


# =============================================================================
# DATA LOADING
# =============================================================================

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/stravika-gold/zapier-insights-data/main"

CSV_FILES = ["workflows", "runs", "run_steps", "audit_events", "external_status"]


def fetch_from_github(base_url=None):
    """
    Fetch all 5 CSV files from a GitHub repo's raw URLs.

    Args:
        base_url: Base URL for raw CSV files (defaults to GITHUB_RAW_BASE)

    Returns:
        dict mapping dataset name -> list of row dicts
    """
    base = base_url or GITHUB_RAW_BASE
    data = {}

    for name in CSV_FILES:
        url = f"{base}/{name}.csv"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        data[name] = list(reader)

    return data


def parse_input_json(input_data):
    """
    Fallback: Parse Zapier input_data from JSON strings (Google Sheets mode).
    """
    def _parse_json_field(field_name):
        raw = input_data.get(field_name, "[]")
        if not raw or raw.strip() == "":
            return []
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []

    return {name: _parse_json_field(name) for name in CSV_FILES}


# =============================================================================
# TIMESTAMP PARSING
# =============================================================================

def _compute_confidence(detection_type, metrics):
    """Compute confidence level (High/Medium/Low) for a detection."""
    if detection_type == "silent_failure":
        drop = 1 - metrics.get("volume_ratio", 1)
        rate = metrics.get("recent_success_rate", 0)
        count = metrics.get("recent_runs_count", 0)
        if drop > 0.7 and rate > 0.95 and count >= 10:
            return "High"
        if drop > 0.4 and rate > 0.90:
            return "Medium"
        return "Low"
    if detection_type == "audit_correlation":
        count = metrics.get("auth_failure_count", 0)
        time_to_first = metrics.get("time_to_first_min", 999)
        if count >= 10 and time_to_first < 60:
            return "High"
        if count >= 5:
            return "Medium"
        return "Low"
    if detection_type == "provider_anomaly":
        ratio = metrics.get("avg_latency_ratio", 1)
        affected = metrics.get("affected_count", 0)
        timeouts = metrics.get("total_timeouts", 0)
        if ratio >= 3.0 and affected >= 2 and timeouts >= 3:
            return "High"
        if ratio >= 2.0 and affected >= 2:
            return "Medium"
        return "Low"
    return "Low"


def _build_audit(workflow_id, detection_type, baseline_window, current_window,
                 baseline_rate, current_rate, delta_pct, total_runs,
                 failed_runs, failure_rate):
    """Build audit record for debugging and calibration."""
    return {
        "workflow_id": workflow_id,
        "detection_type": detection_type,
        "baseline_window": baseline_window,
        "current_window": current_window,
        "baseline_rate": baseline_rate,
        "current_rate": current_rate,
        "delta_pct": delta_pct,
        "total_runs": total_runs,
        "failed_runs": failed_runs,
        "failure_rate": failure_rate,
    }


def _parse_ts(ts_str):
    """Parse ISO timestamp string to datetime."""
    ts_str = ts_str.rstrip("Z")
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")


# =============================================================================
# DETECTION ENGINE
# =============================================================================

def _estimate_degradation_onset(runs, window_start, window_end, baseline_daily_rate):
    """Estimate when volume degradation began using rolling 6h bucket analysis.

    Walks 6h buckets from window_start to window_end. Returns the start of the
    first bucket where run count drops below 50% of the baseline 6h average AND
    stays below that threshold for at least 12 consecutive hours (2 buckets).

    Returns datetime or None if no clear onset found.
    """
    if not runs or baseline_daily_rate <= 0:
        return None

    baseline_bucket_avg = baseline_daily_rate * BUCKET_HOURS / 24
    threshold = baseline_bucket_avg * 0.5

    # Build sorted timestamps for all runs in the full window
    all_ts = sorted(
        _parse_ts(r["started_at"]) for r in runs
        if window_start <= _parse_ts(r["started_at"]) <= window_end
    )

    if not all_ts:
        return None

    # Walk buckets
    bucket_start = window_start
    consecutive_low_start = None
    consecutive_low_hours = 0

    while bucket_start < window_end:
        bucket_end = bucket_start + timedelta(hours=BUCKET_HOURS)
        count = sum(1 for ts in all_ts if bucket_start <= ts < bucket_end)

        if count < threshold:
            if consecutive_low_start is None:
                consecutive_low_start = bucket_start
                consecutive_low_hours = BUCKET_HOURS
            else:
                consecutive_low_hours += BUCKET_HOURS

            if consecutive_low_hours >= 12:
                return consecutive_low_start
        else:
            consecutive_low_start = None
            consecutive_low_hours = 0

        bucket_start = bucket_end

    return consecutive_low_start


def detect_silent_failure(workflow, runs, analysis_end=None):
    """
    Detect silent failure: volume drops >40% while success rate stays >95%.

    Compares last 48h volume against 7-day baseline and expected_runs_per_day.
    """
    if not runs:
        return []

    if analysis_end is None:
        timestamps = [_parse_ts(r["started_at"]) for r in runs]
        analysis_end = max(timestamps)
        # Snap to end of day for clean window boundaries
        analysis_end = analysis_end.replace(hour=23, minute=59, second=59, microsecond=0)

    window_start = analysis_end - timedelta(hours=RECENT_WINDOW_HOURS)
    baseline_start = analysis_end - timedelta(days=BASELINE_WINDOW_DAYS)

    recent_runs = [r for r in runs if _parse_ts(r["started_at"]) >= window_start]
    baseline_runs = [
        r for r in runs
        if baseline_start <= _parse_ts(r["started_at"]) < window_start
    ]

    if not baseline_runs:
        return []

    recent_days = RECENT_WINDOW_HOURS / 24
    baseline_days = max(1, (window_start - baseline_start).days)

    recent_volume_per_day = len(recent_runs) / recent_days
    baseline_volume_per_day = len(baseline_runs) / baseline_days
    expected_volume = int(workflow.get("expected_runs_per_day", 0))

    reference_volume = max(baseline_volume_per_day, expected_volume)

    if reference_volume == 0:
        return []

    volume_ratio = recent_volume_per_day / reference_volume

    recent_successes = sum(1 for r in recent_runs if r["status"] == "success")
    recent_success_rate = recent_successes / len(recent_runs) if recent_runs else 0

    if volume_ratio < 0.6 and recent_success_rate > 0.95:
        drop_pct = round((1 - volume_ratio) * 100, 1)
        estimated_daily_impact = round(reference_volume - recent_volume_per_day, 0)

        confidence = _compute_confidence("silent_failure", {
            "volume_ratio": volume_ratio,
            "recent_success_rate": recent_success_rate,
            "recent_runs_count": len(recent_runs),
        })

        baseline_label = f"{baseline_start.strftime('%b %d')}-{window_start.strftime('%b %d')}"
        current_label = f"{window_start.strftime('%b %d')}-{analysis_end.strftime('%b %d')}"

        # --- Timestamp: last processed run (fact) ---
        recent_timestamps = [_parse_ts(r["started_at"]) for r in recent_runs]
        last_processed_run = max(recent_timestamps) if recent_timestamps else None
        last_processed_str = (
            last_processed_run.strftime("%Y-%m-%d %H:%M")
            if last_processed_run else "unknown"
        )

        # --- Timestamp: degradation began (inference) ---
        # Rolling 6h bucket analysis over all runs in baseline+recent window
        degradation_began = _estimate_degradation_onset(
            runs, baseline_start, analysis_end, baseline_volume_per_day
        )
        degradation_began_str = (
            f"~{degradation_began.strftime('%Y-%m-%d %H:%M')}"
            if degradation_began else None
        )

        audit = _build_audit(
            workflow_id=workflow["workflow_id"],
            detection_type="silent_failure",
            baseline_window=baseline_label,
            current_window=current_label,
            baseline_rate=round(baseline_volume_per_day, 1),
            current_rate=round(recent_volume_per_day, 1),
            delta_pct=round(-drop_pct, 1),
            total_runs=len(recent_runs),
            failed_runs=len(recent_runs) - recent_successes,
            failure_rate=round((1 - recent_success_rate) * 100, 2),
        )

        return [{
            "type": "silent_failure",
            "confidence": confidence,
            "detail": (
                f"Volume dropped from ~{reference_volume:.0f}/day to "
                f"~{recent_volume_per_day:.0f}/day "
                f"({BASELINE_WINDOW_DAYS}-day baseline vs last {RECENT_WINDOW_HOURS}h, "
                f"success rate {recent_success_rate:.0%}). "
                f"Possible trigger break or upstream event suppression."
            ),
            "metrics": {
                "reference_volume_per_day": round(reference_volume, 1),
                "recent_volume_per_day": round(recent_volume_per_day, 1),
                "volume_ratio": round(volume_ratio, 3),
                "recent_success_rate": round(recent_success_rate, 4),
                "estimated_daily_impact": estimated_daily_impact,
                "impact_label": "events/day not processed",
                "baseline_window": baseline_label,
                "current_window": current_label,
                "last_processed_run": last_processed_str,
                "degradation_began": degradation_began_str,
            },
            "audit": audit,
        }]

    return []


def detect_audit_correlation(workflow, runs, audit_events, window_hours=3):
    """
    Detect audit correlation: credential update followed by AUTH_* failures.

    Looks for CREDENTIAL_UPDATED events and checks for AUTH failures within window.
    """
    wf_id = workflow["workflow_id"]
    detections = []

    cred_updates = [
        e for e in audit_events
        if e.get("event_type") == "CREDENTIAL_UPDATED"
        and e.get("workflow_id") == wf_id
    ]

    for event in cred_updates:
        event_time = _parse_ts(event["timestamp"])
        window_end = event_time + timedelta(hours=window_hours)

        auth_failures = [
            r for r in runs
            if r.get("error_category", "").startswith("AUTH")
            and event_time <= _parse_ts(r["started_at"]) <= window_end
            and r["status"] == "failed"
        ]

        if len(auth_failures) >= 3:
            first_failure = min(auth_failures, key=lambda r: r["started_at"])
            last_failure = max(auth_failures, key=lambda r: r["started_at"])

            # Calculate time relative to credential rotation (not first-to-last span)
            time_to_first_min = (
                _parse_ts(first_failure["started_at"]) - event_time
            ).total_seconds() / 60
            time_to_last_min = (
                _parse_ts(last_failure["started_at"]) - event_time
            ).total_seconds() / 60
            failure_span_min = time_to_last_min - time_to_first_min

            failed_steps = set(
                r.get("failed_step_id", "") for r in auth_failures
                if r.get("failed_step_id")
            )

            confidence = _compute_confidence("audit_correlation", {
                "auth_failure_count": len(auth_failures),
                "time_to_first_min": time_to_first_min,
                "window_hours": window_hours,
            })

            audit = _build_audit(
                workflow_id=wf_id,
                detection_type="audit_correlation",
                baseline_window="N/A",
                current_window=f"{event_time.strftime('%b %d %H:%M')}-{window_end.strftime('%H:%M')}",
                baseline_rate=0,
                current_rate=0,
                delta_pct=0,
                total_runs=len(auth_failures),
                failed_runs=len(auth_failures),
                failure_rate=100.0,
            )

            detections.append({
                "type": "audit_correlation",
                "confidence": confidence,
                "detail": (
                    f"{len(auth_failures)} {auth_failures[0]['error_category']} failures "
                    f"between {time_to_first_min:.0f}min and {time_to_last_min:.0f}min "
                    f"after credential rotation"
                    f"{' at step ' + ', '.join(failed_steps) if failed_steps else ''}."
                ),
                "metrics": {
                    "audit_event_type": event["event_type"],
                    "audit_timestamp": event["timestamp"],
                    "auth_failure_count": len(auth_failures),
                    "time_to_first_failure_min": round(time_to_first_min, 1),
                    "time_to_last_failure_min": round(time_to_last_min, 1),
                    "failure_span_minutes": round(failure_span_min, 1),
                    "error_categories": list(set(r["error_category"] for r in auth_failures)),
                    "failed_steps": list(failed_steps),
                },
                "audit": audit,
            })

    return detections


def detect_provider_anomaly(workflows, all_runs, run_steps, external_status):
    """
    Detect cross-workflow provider anomaly: 2+ workflows with same provider
    show 2x+ latency increase, correlated with provider degradation.
    """
    detections = []

    degradation_events = [
        e for e in external_status
        if e.get("status") in ("degraded", "outage")
    ]

    run_to_wf = {r["run_id"]: r["workflow_id"] for r in all_runs}

    for event in degradation_events:
        provider = event["provider"]
        degraded_start = _parse_ts(event["started_at"])
        degraded_end = _parse_ts(event["ended_at"])

        # Find workflows using this provider via run_steps
        wf_ids_with_provider = set()
        for step in run_steps:
            if step.get("app", "").lower() == provider.lower():
                wf_id = run_to_wf.get(step["run_id"])
                if wf_id:
                    wf_ids_with_provider.add(wf_id)

        provider_workflows = [
            wf for wf in workflows if wf["workflow_id"] in wf_ids_with_provider
        ]

        if len(provider_workflows) < 2:
            continue

        affected_workflows = []
        for wf in provider_workflows:
            wf_id = wf["workflow_id"]
            wf_runs = [r for r in all_runs if r["workflow_id"] == wf_id]

            during_runs = [
                r for r in wf_runs
                if degraded_start <= _parse_ts(r["started_at"]) <= degraded_end
            ]

            # Baseline: BASELINE_WINDOW_DAYS before degradation
            baseline_start = degraded_start - timedelta(days=BASELINE_WINDOW_DAYS)
            baseline_runs = [
                r for r in wf_runs
                if baseline_start <= _parse_ts(r["started_at"]) < degraded_start
            ]

            if not during_runs or not baseline_runs:
                continue

            # Median latency (robust to outliers)
            during_median = median([int(r["duration_ms"]) for r in during_runs])
            baseline_median = median([int(r["duration_ms"]) for r in baseline_runs])

            if baseline_median == 0:
                continue

            latency_ratio = during_median / baseline_median
            timeout_count = sum(
                1 for r in during_runs if r.get("error_category") == "TIMEOUT"
            )

            if latency_ratio >= 2.0:
                affected_workflows.append({
                    "workflow_id": wf_id,
                    "workflow_name": wf["workflow_name"],
                    "latency_ratio": round(latency_ratio, 1),
                    "during_median_ms": round(during_median),
                    "baseline_median_ms": round(baseline_median),
                    "timeout_count": timeout_count,
                    "runs_in_window": len(during_runs),
                })

        if len(affected_workflows) >= 2:
            avg_ratio = sum(w["latency_ratio"] for w in affected_workflows) / len(affected_workflows)
            wf_names = [w["workflow_name"] for w in affected_workflows]
            total_timeouts = sum(w["timeout_count"] for w in affected_workflows)

            # Primary = worst-affected workflow (highest latency ratio)
            primary_wf = max(affected_workflows, key=lambda w: w["latency_ratio"])

            confidence = _compute_confidence("provider_anomaly", {
                "avg_latency_ratio": avg_ratio,
                "affected_count": len(affected_workflows),
                "total_timeouts": total_timeouts,
            })

            audit = _build_audit(
                workflow_id=primary_wf["workflow_id"],
                detection_type="provider_anomaly",
                baseline_window=f"{(degraded_start - timedelta(days=BASELINE_WINDOW_DAYS)).strftime('%b %d')}-{degraded_start.strftime('%b %d')}",
                current_window=f"{degraded_start.strftime('%b %d %H:%M')}-{degraded_end.strftime('%H:%M')}",
                baseline_rate=primary_wf["baseline_median_ms"],
                current_rate=primary_wf["during_median_ms"],
                delta_pct=round((primary_wf["latency_ratio"] - 1) * 100, 1),
                total_runs=primary_wf["runs_in_window"],
                failed_runs=primary_wf["timeout_count"],
                failure_rate=round(primary_wf["timeout_count"] / max(1, primary_wf["runs_in_window"]) * 100, 1),
            )

            detections.append({
                "type": "provider_anomaly",
                "confidence": confidence,
                "detail": (
                    f"Workflows using {provider} show {avg_ratio:.1f}x latency increase "
                    f"during provider degradation window "
                    f"({degraded_start.strftime('%b %d %H:%M')}-{degraded_end.strftime('%H:%M')}). "
                    f"Affected: {', '.join(wf_names)}."
                    + (f" {total_timeouts} timeout failures." if total_timeouts else "")
                ),
                "metrics": {
                    "provider": provider,
                    "degradation_start": event["started_at"],
                    "degradation_end": event["ended_at"],
                    "affected_workflows": affected_workflows,
                    "avg_latency_ratio": round(avg_ratio, 1),
                    "total_timeouts": total_timeouts,
                    "primary_workflow_id": primary_wf["workflow_id"],
                    "primary_workflow_timeouts": primary_wf["timeout_count"],
                },
                "audit": audit,
            })

    return detections


def run_all_detections(workflows, runs, run_steps, audit_events, external_status):
    """Run all detection scenarios across all workflows."""
    results = defaultdict(list)

    for wf in workflows:
        wf_id = wf["workflow_id"]
        wf_runs = [r for r in runs if r["workflow_id"] == wf_id]

        results[wf_id].extend(detect_silent_failure(wf, wf_runs))
        results[wf_id].extend(detect_audit_correlation(wf, wf_runs, audit_events))

    provider_detections = detect_provider_anomaly(
        workflows, runs, run_steps, external_status
    )
    for detection in provider_detections:
        for affected_wf in detection["metrics"].get("affected_workflows", []):
            wf_id = affected_wf["workflow_id"]
            results[wf_id].append(detection)

    return dict(results)


# =============================================================================
# HEALTH SCORE
# =============================================================================

def calculate_health_score(workflow, runs, detections, external_status=None):
    """
    Calculate explainable health score for a workflow.

    Starts at 100. Deductions applied per detected signal.
    Bands: 86-100 Healthy | 70-85 Watch | <70 At Risk
    """
    score = 100
    deductions = []

    # --- 1. Failure rate penalty (up to -50) ---
    # Failure rate = failed_runs / total_runs (run-level, not step-level)
    if runs:
        timestamps = [_parse_ts(r["started_at"]) for r in runs]
        latest = max(timestamps)
        window_start = latest - timedelta(days=7)
        recent_runs = [r for r in runs if _parse_ts(r["started_at"]) >= window_start]

        if recent_runs:
            failed = sum(1 for r in recent_runs if r["status"] == "failed")
            total = len(recent_runs)
            fail_rate = failed / total

            if fail_rate > 0.02:
                penalty = min(50, max(5, int((fail_rate - 0.02) / 0.48 * 50)))
                if penalty > 0:
                    score -= penalty
                    deductions.append({
                        "signal": "fail_rate",
                        "points": -penalty,
                        "detail": (
                            f"Failure rate {fail_rate:.1%} "
                            f"({failed}/{total} runs, last 7 days) "
                            f"exceeds 2% baseline."
                        ),
                    })

    # --- 2. Latency spike (-10) ---
    latency_deduction = _check_latency_spike(runs)
    if latency_deduction:
        score -= 10
        deductions.append(latency_deduction)

    # --- 3. Silent volume drop (-35) ---
    # Weighted heavily: silent degradation is the most dangerous signal
    # because there's no error to alert on -- workflows just stop working.
    silent_detections = [d for d in detections if d["type"] == "silent_failure"]
    if silent_detections:
        score -= 35
        d = silent_detections[0]
        deductions.append({
            "signal": "silent_failure",
            "points": -35,
            "detail": d["detail"],
            "metrics": d.get("metrics", {}),
            "confidence": d.get("confidence", ""),
        })

    # --- 4. Audit-correlated failure spike (-15) ---
    audit_detections = [d for d in detections if d["type"] == "audit_correlation"]
    if audit_detections:
        score -= 15
        d = audit_detections[0]
        deductions.append({
            "signal": "audit_correlation",
            "points": -15,
            "detail": d["detail"],
            "metrics": d.get("metrics", {}),
            "confidence": d.get("confidence", ""),
        })

    # --- 5. External incident overlap (-15) ---
    provider_detections = [d for d in detections if d["type"] == "provider_anomaly"]
    if provider_detections:
        score -= 15
        d = provider_detections[0]
        deductions.append({
            "signal": "external_incident",
            "points": -15,
            "detail": d["detail"],
            "metrics": d.get("metrics", {}),
            "confidence": d.get("confidence", ""),
        })

    score = max(0, min(100, score))

    if score > 85:
        status = "healthy"
    elif score >= 70:
        status = "watch"
    else:
        status = "at_risk"

    return {
        "health_score": score,
        "status": status,
        "deductions": deductions,
    }


def _check_latency_spike(runs, threshold_ratio=2.0):
    """Check if recent latency (last 24h) is 2x+ the 7-day baseline."""
    if not runs:
        return None

    timestamps = [_parse_ts(r["started_at"]) for r in runs]
    latest = max(timestamps)

    recent_cutoff = latest - timedelta(hours=24)
    baseline_start = latest - timedelta(days=7)

    recent_durations = [
        int(r["duration_ms"]) for r in runs
        if _parse_ts(r["started_at"]) >= recent_cutoff
        and r["status"] == "success"
    ]

    baseline_durations = [
        int(r["duration_ms"]) for r in runs
        if baseline_start <= _parse_ts(r["started_at"]) < recent_cutoff
        and r["status"] == "success"
    ]

    if not recent_durations or not baseline_durations:
        return None

    recent_median = median(recent_durations)
    baseline_median = median(baseline_durations)

    if baseline_median == 0:
        return None

    ratio = recent_median / baseline_median

    if ratio >= threshold_ratio:
        return {
            "signal": "latency_spike",
            "points": -10,
            "detail": (
                f"Median latency {recent_median:.0f}ms vs "
                f"{baseline_median:.0f}ms baseline "
                f"({ratio:.1f}x increase)."
            ),
        }

    return None


# =============================================================================
# SLACK FORMATTING
# =============================================================================

STATUS_EMOJI = {
    "at_risk": ":rotating_light:",
    "watch": ":warning:",
    "healthy": ":white_check_mark:",
}

STATUS_LABELS = {
    "at_risk": "AT RISK",
    "watch": "WATCH",
    "healthy": "Healthy",
}

# Why-this-matters interpretation by signal type
SIGNAL_INTERPRETATION = {
    "silent_failure": (
        "Likely trigger break or upstream event suppression "
        "(no error signal \u2014 silent degradation)"
    ),
    "audit_correlation": (
        "High probability the credential update caused the failure spike"
    ),
    "external_incident": (
        "Cross-workflow impact suggests upstream provider issue"
    ),
    "fail_rate": (
        "Elevated failure rate may indicate configuration or connectivity issue"
    ),
    "latency_spike": (
        "Performance degradation may impact downstream processes"
    ),
}

# Macro summary category labels
SIGNAL_CATEGORY = {
    "silent_failure": "silent degradation",
    "audit_correlation": "credential-related failure",
    "external_incident": "provider anomaly",
    "fail_rate": "elevated failure rate",
    "latency_spike": "latency spike",
}

MAX_SIGNALS_PER_CARD = 2


def _clean_detail(detail, signal):
    """Extract clean observation lines from a deduction detail string."""
    if signal == "silent_failure":
        lines = []
        vol = re.match(r'Volume dropped from (~[\d]+/day) to (~[\d]+/day)', detail)
        rate = re.search(r'success rate ([\d.]+%)', detail)
        if vol:
            lines.append(f"Volume dropped from {vol.group(1)} to {vol.group(2)}")
        if rate:
            lines.append(f"Success rate remains {rate.group(1)}")
        return lines or [detail.split(".")[0]]

    if signal == "fail_rate":
        match = re.match(r'Failure rate ([\d.]+%) \((\d+/\d+) runs', detail)
        if match:
            return [f"Failure rate {match.group(1)} ({match.group(2)} runs)"]
        return [detail.split("exceeds")[0].strip()]

    if signal == "audit_correlation":
        return [detail.rstrip(".")]

    if signal == "external_incident":
        lines = []
        ratio = re.search(r'([\d.]+)x latency increase', detail)
        provider = re.search(r'using (\w+)', detail)
        timeouts = re.search(r'(\d+) timeout failure', detail)
        if ratio:
            prov = provider.group(1) if provider else "provider"
            lines.append(f"{ratio.group(1)}x latency increase during {prov} degradation window")
        if timeouts:
            lines.append(f"{timeouts.group(1)} timeout failures")
        return lines or [detail.rstrip(".")]

    if signal == "latency_spike":
        return [detail.rstrip(".")]

    return [detail.rstrip(".")]


def _format_evidence(deduction):
    """Format evidence line from deduction metrics."""
    signal = deduction.get("signal", "")
    metrics = deduction.get("metrics", {})
    if not metrics:
        return None

    if signal == "silent_failure":
        ref_vol = metrics.get("reference_volume_per_day")
        recent_vol = metrics.get("recent_volume_per_day")
        if ref_vol and recent_vol:
            return f"Baseline ~{ref_vol:.0f}/day vs current ~{recent_vol:.0f}/day (last 48h vs 7-day avg)"

    if signal == "audit_correlation":
        ts = metrics.get("audit_timestamp", "")
        count = metrics.get("auth_failure_count", 0)
        t_first = metrics.get("time_to_first_failure_min")
        t_last = metrics.get("time_to_last_failure_min")
        if ts and count and t_first is not None and t_last is not None:
            ts_short = ts[:16].replace("T", " ")
            return f"{count} failures {t_first:.0f}min-{t_last:.0f}min after credential change at {ts_short}"
        elif ts and count:
            ts_short = ts[:16].replace("T", " ")
            return f"{count} failures after credential change at {ts_short}"

    if signal == "external_incident":
        affected = metrics.get("affected_workflows", [])
        provider = metrics.get("provider", "")
        start = metrics.get("degradation_start", "")
        end = metrics.get("degradation_end", "")
        primary_timeouts = metrics.get("primary_workflow_timeouts")
        total_timeouts = metrics.get("total_timeouts", 0)
        if start and end:
            s = start[11:16]
            e = end[11:16]
            parts = [f"{provider} degradation {s}-{e}"]
            if primary_timeouts is not None:
                parts.append(f"{primary_timeouts} timeouts (this workflow)")
            elif total_timeouts:
                parts.append(f"{total_timeouts} timeouts")
            return " | ".join(parts)

    if signal == "fail_rate":
        return None  # Detail string already contains the evidence

    if signal == "latency_spike":
        return None  # Detail string already contains the evidence

    return None


def format_insight_card(insight):
    """
    Format a single insight as an executive-style Slack card.

    Sections: What changed (observation), Why this matters (interpretation),
    Evidence (metrics), Suggested action.
    Limits to top MAX_SIGNALS_PER_CARD deductions by severity.
    """
    emoji = STATUS_EMOJI.get(insight["status"], ":question:")
    label = STATUS_LABELS.get(insight["status"], insight["status"])
    score = insight["health_score"]
    name = insight["workflow_name"]

    # Sort deductions by severity (most impactful first), limit to top N
    deductions = sorted(
        insight.get("deductions", []),
        key=lambda d: abs(d.get("points", 0)),
        reverse=True,
    )
    extra_count = max(0, len(deductions) - MAX_SIGNALS_PER_CARD)
    deductions = deductions[:MAX_SIGNALS_PER_CARD]

    lines = [
        f"{emoji} *{name}*",
        f"Health Score: {score} \u2014 {label}",
        "",
        "*What changed*",
    ]

    for d in deductions:
        for obs in _clean_detail(d["detail"], d.get("signal", "")):
            lines.append(f"\u2022 {obs}")

    if extra_count > 0:
        lines.append(f"_+{extra_count} more signal{'s' if extra_count > 1 else ''}_")

    # Why this matters
    seen = set()
    interpretations = []
    for d in deductions:
        s = d.get("signal", "")
        if s in SIGNAL_INTERPRETATION and s not in seen:
            interpretations.append(SIGNAL_INTERPRETATION[s])
            seen.add(s)

    if interpretations:
        lines.append("")
        lines.append("*Why this matters*")
        for interp in interpretations:
            lines.append(interp)

    # Evidence
    evidence_lines = []
    for d in deductions:
        ev = _format_evidence(d)
        if ev:
            evidence_lines.append(ev)

    if evidence_lines:
        lines.append("")
        lines.append("*Evidence*")
        for ev in evidence_lines:
            lines.append(f"_{ev}_")

    if insight.get("suggested_action"):
        lines.append("")
        lines.append("*Suggested action*")
        lines.append(insight["suggested_action"])

    return "\n".join(lines)


def _macro_summary(insights):
    """Build one-line macro summary from insight signals."""
    signal_counts = Counter()
    for insight in insights:
        for d in insight.get("deductions", []):
            signal = d.get("signal", "")
            if signal in SIGNAL_CATEGORY:
                signal_counts[signal] += 1
    if not signal_counts:
        return ""
    parts = []
    for signal, count in signal_counts.items():
        parts.append(f"{count} {SIGNAL_CATEGORY[signal]}")
    return " \u00b7 ".join(parts)


def _band_counts(insights):
    """Build band count string like '1 At Risk, 2 Watch'."""
    counts = Counter(i.get("status", "") for i in insights)
    parts = []
    if counts.get("at_risk", 0) > 0:
        parts.append(f"{counts['at_risk']} At Risk")
    if counts.get("watch", 0) > 0:
        parts.append(f"{counts['watch']} Watch")
    return ", ".join(parts)


def format_all_insights(insights_output, total_workflows=None):
    """
    Format the full insights output for Slack.

    Executive header with band counts and macro summary, then per-workflow cards
    with What changed / Why this matters / Evidence / Suggested action sections.
    """
    count = insights_output.get("insights_count", 0)
    if count == 0:
        monitored = f"{total_workflows} workflows monitored. " if total_workflows else ""
        return (
            f":white_check_mark: *Zapier Insights \u2014 All Workflows Healthy*\n"
            f"{monitored}No material changes in the last 24 hours."
        )

    insights = insights_output.get("insights", [])
    wf_word = "Workflow" if count == 1 else "Workflows"
    need_word = "Needs" if count == 1 else "Need"

    bands = _band_counts(insights)
    header = (
        f":rotating_light: *Zapier Insights \u2014 "
        f"{count} {wf_word} {need_word} Attention*"
    )

    summary = _macro_summary(insights)
    cards = [format_insight_card(i) for i in insights]

    parts = [header]
    if bands:
        parts.append(bands)
    if summary:
        parts.append(f"_{summary}_")
    parts.append("")
    parts.append("\n\n---\n\n".join(cards))

    return "\n".join(parts)


def build_suggested_action(detections):
    """Generate an evidence-specific suggested action based on detected signals."""
    types = [d["type"] for d in detections]

    if "audit_correlation" in types:
        for d in detections:
            if d["type"] == "audit_correlation":
                m = d.get("metrics", {})
                steps = m.get("failed_steps", [])
                count = m.get("auth_failure_count", 0)
                window = m.get("failure_window_minutes", 0)
                step_str = f" step {', '.join(steps)}" if steps else ""
                detail = ""
                if count and window:
                    detail = f" {count} failures within {window:.0f}min of credential change."
                return f"Re-authenticate the connection used by{step_str}.{detail}"
        return "Re-authenticate the affected connection."

    if "silent_failure" in types:
        for d in detections:
            if d["type"] == "silent_failure":
                m = d.get("metrics", {})
                ref = m.get("reference_volume_per_day")
                recent = m.get("recent_volume_per_day")
                if ref and recent:
                    return (
                        f"Check Zap trigger configuration and upstream event source. "
                        f"Volume dropped from ~{ref:.0f}/day to ~{recent:.0f}/day."
                    )
        return "Check Zap trigger configuration and upstream event source."

    if "provider_anomaly" in types:
        for d in detections:
            if d["type"] == "provider_anomaly":
                m = d.get("metrics", {})
                provider = m.get("provider", "the provider")
                start = m.get("degradation_start", "")
                end = m.get("degradation_end", "")
                if start and end:
                    s = start[11:16]
                    e = end[11:16]
                    return (
                        f"Check {provider} status (degraded {s}\u2013{e}). "
                        f"If stable now, add retry logic or temporary alerting."
                    )
                return f"Check {provider} status page. Consider adding retry logic or alerting."
        return "Check provider status page and consider retry logic."

    return "Review workflow configuration and recent changes."


# =============================================================================
# THREE-LAYER FORMATTING (Ambient -> Detail -> LLM)
# =============================================================================

# Compact action labels for ambient cards
COMPACT_ACTIONS = {
    "silent_failure": "verify trigger is still receiving events + upstream source is firing",
    "audit_correlation": "re-authenticate the affected connection and run a test with a sample record",
    "external_incident": "check provider status page; if resolved, consider retry logic with exponential backoff",
    "fail_rate": "review error logs and recent configuration changes",
    "latency_spike": "check provider performance and consider adding timeout handling",
}


def _compact_observation(insight):
    """Build a single-line observation from the top deduction for ambient cards."""
    deductions = sorted(
        insight.get("deductions", []),
        key=lambda d: abs(d.get("points", 0)),
        reverse=True,
    )
    if not deductions:
        return "Health score declined"

    top = deductions[0]
    signal = top.get("signal", "")
    metrics = top.get("metrics", {})

    if signal == "silent_failure":
        ref = metrics.get("reference_volume_per_day")
        recent = metrics.get("recent_volume_per_day")
        rate = metrics.get("recent_success_rate")
        impact = metrics.get("estimated_daily_impact")
        cur_window = metrics.get("current_window", "48h")
        if ref and recent:
            pct = int(round((1 - recent / ref) * 100))
            obs = f"Volume -{pct}% (baseline {ref:.0f}/day \u2192 {recent:.0f}/day last {cur_window})."
            if rate and rate > 0.95:
                obs += f" Success {rate * 100:.0f}% \u2014 silent degradation."
            impact_line = ""
            if impact and impact > 0:
                impact_line = f"\nEst. impact: ~{impact:.0f} events/day not processed."
            return obs + impact_line
        return "Significant volume drop with no error signal."

    if signal == "audit_correlation":
        count = metrics.get("auth_failure_count", 0)
        confidence = top.get("confidence", "")
        conf_str = f" ({confidence})" if confidence else ""
        if count:
            return f"AUTH_EXPIRED correlated with credential rotation{conf_str}. {count} failures detected."
        return f"Auth failures correlated with credential change{conf_str}."

    if signal == "external_incident":
        ratio = metrics.get("avg_latency_ratio")
        provider = metrics.get("provider", "provider")
        confidence = top.get("confidence", "")
        conf_str = f" ({confidence})" if confidence else ""
        # Use per-workflow timeouts for the ambient card (not aggregate)
        timeouts = metrics.get("primary_workflow_timeouts", metrics.get("total_timeouts", 0))
        parts = []
        if ratio:
            parts.append(f"Latency spike aligns with {provider} degraded window{conf_str}")
        if timeouts:
            parts.append(f"{timeouts} timeouts")
        return ". ".join(parts) + "." if parts else "Provider incident detected."

    if signal == "fail_rate":
        detail = top.get("detail", "")
        match = re.match(r'Failure rate ([\d.]+%)', detail)
        if match:
            return f"Failure rate elevated to {match.group(1)}."
        return "Elevated failure rate."

    return top.get("detail", "Health score declined").split(".")[0] + "."


def _compact_action(insight):
    """Get a short action string for the ambient card."""
    deductions = sorted(
        insight.get("deductions", []),
        key=lambda d: abs(d.get("points", 0)),
        reverse=True,
    )
    if deductions:
        signal = deductions[0].get("signal", "")
        if signal in COMPACT_ACTIONS:
            return COMPACT_ACTIONS[signal]
    return "Review workflow"


def format_ambient_card(worst_insight, watch_count=0, total_workflows=None):
    """
    Format Layer 1: compact ambient card for the single worst workflow.
    Posted to the Slack channel. 3-4 lines max.
    """
    if worst_insight is None:
        monitored = f"{total_workflows} workflows monitored. " if total_workflows else ""
        return (
            f":white_check_mark: *Zapier Insights \u2014 All Workflows Healthy*\n"
            f"{monitored}No material changes in the last 24 hours."
        )

    emoji = STATUS_EMOJI.get(worst_insight["status"], ":question:")
    label = STATUS_LABELS.get(worst_insight["status"], worst_insight["status"])
    name = worst_insight["workflow_name"]
    score = worst_insight["health_score"]

    observation = _compact_observation(worst_insight)
    action = _compact_action(worst_insight)

    lines = [
        f"{emoji} *{name}* \u2014 {label} ({score})",
        observation,
        f"Next: {action}.",
    ]

    footer_parts = ["React :eyes: for drilldown"]
    if watch_count > 0:
        wf_word = "workflow" if watch_count == 1 else "workflows"
        footer_parts.append(f"{watch_count} {wf_word} on Watch")
    lines.append(f"_{'. '.join(footer_parts)}._")

    return "\n".join(lines)


def _detail_metrics(insight):
    """Extract key metrics from deductions for the detail thread."""
    lines = []
    for d in sorted(
        insight.get("deductions", []),
        key=lambda dd: abs(dd.get("points", 0)),
        reverse=True,
    ):
        signal = d.get("signal", "")
        metrics = d.get("metrics", {})

        if signal == "silent_failure":
            ref = metrics.get("reference_volume_per_day")
            recent = metrics.get("recent_volume_per_day")
            rate = metrics.get("recent_success_rate")
            impact = metrics.get("estimated_daily_impact")
            bl_window = metrics.get("baseline_window", "7-day")
            cur_window = metrics.get("current_window", "48h")
            last_run = metrics.get("last_processed_run")
            deg_began = metrics.get("degradation_began")
            if ref:
                lines.append(f"Baseline: ~{ref:.0f}/day ({bl_window})")
            if recent:
                lines.append(f"Current: ~{recent:.0f}/day ({cur_window})")
            if rate is not None:
                lines.append(f"Success rate: {rate * 100:.0f}%")
            if last_run:
                lines.append(f"Last processed run: {last_run}")
            if deg_began:
                lines.append(f"Degradation began: {deg_began} (inferred from volume drop vs baseline)")
            if impact and impact > 0:
                lines.append(f"Est. impact: ~{impact:.0f} events/day not processed")

        elif signal == "audit_correlation":
            ts = metrics.get("audit_timestamp", "")
            count = metrics.get("auth_failure_count", 0)
            t_first = metrics.get("time_to_first_failure_min")
            t_last = metrics.get("time_to_last_failure_min")
            steps = metrics.get("failed_steps", [])
            if ts:
                lines.append(f"Credential change: {ts[:16].replace('T', ' ')}")
            if count and t_first is not None and t_last is not None:
                lines.append(f"Auth failures: {count} ({t_first:.0f}min-{t_last:.0f}min after rotation)")
            elif count:
                lines.append(f"Auth failures: {count}")
            if steps:
                lines.append(f"Affected step: {', '.join(steps)}")

        elif signal == "external_incident":
            provider = metrics.get("provider", "")
            start = metrics.get("degradation_start", "")
            end = metrics.get("degradation_end", "")
            # Per-workflow timeouts for this card, total for provider-level
            primary_timeouts = metrics.get("primary_workflow_timeouts")
            total_timeouts = metrics.get("total_timeouts", 0)
            affected = metrics.get("affected_workflows", [])
            if provider and start and end:
                lines.append(f"Provider: {provider} (degraded {start[11:16]}\u2013{end[11:16]})")
            if primary_timeouts is not None:
                lines.append(f"Timeout failures: {primary_timeouts} (this workflow)")
                if total_timeouts and total_timeouts != primary_timeouts:
                    lines.append(f"Total across affected workflows: {total_timeouts}")
            elif total_timeouts:
                lines.append(f"Timeout failures: {total_timeouts}")
            if len(affected) > 1:
                lines.append(f"Affected workflows: {len(affected)}")

        elif signal == "fail_rate":
            detail = d.get("detail", "")
            match = re.match(r'Failure rate ([\d.]+%) \((\d+/\d+) runs', detail)
            if match:
                lines.append(f"Failure rate: {match.group(1)} ({match.group(2)} runs, last 7 days)")

    return lines


def _watch_summary_line(insight):
    """Build a one-liner summary for a Watch workflow."""
    top = sorted(
        insight.get("deductions", []),
        key=lambda d: abs(d.get("points", 0)),
        reverse=True,
    )
    name = insight["workflow_name"]
    score = insight["health_score"]

    if not top:
        return f"\u2022 {name} ({score})"

    d = top[0]
    signal = d.get("signal", "")
    metrics = d.get("metrics", {})

    if signal == "audit_correlation":
        count = metrics.get("auth_failure_count", 0)
        confidence = d.get("confidence", "")
        conf_str = f" ({confidence})" if confidence else ""
        return f"\u2022 {name} ({score}) \u2014 AUTH_EXPIRED correlated with credential rotation{conf_str}"

    if signal == "external_incident":
        ratio = metrics.get("avg_latency_ratio")
        provider = metrics.get("provider", "provider")
        confidence = d.get("confidence", "")
        conf_str = f" ({confidence})" if confidence else ""
        if ratio:
            return f"\u2022 {name} ({score}) \u2014 latency spike aligns with {provider} degraded window{conf_str}"
        return f"\u2022 {name} ({score}) \u2014 {provider} degradation impact{conf_str}"

    if signal == "fail_rate":
        detail = d.get("detail", "")
        match = re.match(r'Failure rate ([\d.]+%)', detail)
        if match:
            return f"\u2022 {name} ({score}) \u2014 Failure rate {match.group(1)}"

    return f"\u2022 {name} ({score}) \u2014 {SIGNAL_CATEGORY.get(signal, 'issue detected')}"


def format_detail_thread(worst_insight, watch_insights=None):
    """
    Format Layer 2: deterministic detail for the thread auto-reply.
    Health score breakdown + metrics for worst workflow, plus Watch summaries.
    No LLM -- pure rule-based data.
    """
    lines = []

    lines.append("*Health Score Breakdown*")
    for d in sorted(
        worst_insight.get("deductions", []),
        key=lambda dd: abs(dd.get("points", 0)),
        reverse=True,
    ):
        signal_label = SIGNAL_CATEGORY.get(d.get("signal", ""), d.get("signal", "unknown"))
        points = d.get("points", 0)
        confidence = d.get("confidence", "")
        conf_str = f" (Confidence: {confidence})" if confidence else ""
        lines.append(f"\u2022 {signal_label.title()}: {points}{conf_str}")

    detail_lines = _detail_metrics(worst_insight)
    if detail_lines:
        lines.append("")
        lines.append("*Metrics*")
        for dl in detail_lines:
            lines.append(dl)

    if watch_insights:
        lines.append("")
        lines.append("---")
        lines.append("")
        watch_word = "workflow" if len(watch_insights) == 1 else "workflows"
        lines.append(f"*Also on Watch ({len(watch_insights)} {watch_word}):*")
        for wi in watch_insights:
            lines.append(_watch_summary_line(wi))

    return "\n".join(lines)


# =============================================================================
# PIPELINE
# =============================================================================

def build_insights(workflows, runs, run_steps, audit_events, external_status):
    """Run full detection + scoring pipeline. Returns structured insights dict."""
    detections_by_wf = run_all_detections(
        workflows, runs, run_steps, audit_events, external_status
    )

    insights = []

    for wf in workflows:
        wf_id = wf["workflow_id"]
        wf_runs = [r for r in runs if r["workflow_id"] == wf_id]
        wf_detections = detections_by_wf.get(wf_id, [])

        score_result = calculate_health_score(
            wf, wf_runs, wf_detections, external_status
        )

        if score_result["status"] in ("watch", "at_risk"):
            suggested_action = build_suggested_action(wf_detections)

            insights.append({
                "workflow_id": wf_id,
                "workflow_name": wf["workflow_name"],
                "health_score": score_result["health_score"],
                "status": score_result["status"],
                "deductions": score_result["deductions"],
                "suggested_action": suggested_action,
            })

    # Sort by health score (worst first), limit to 3
    insights.sort(key=lambda i: i["health_score"])
    insights = insights[:3]

    return {
        "insights_count": len(insights),
        "insights": insights,
    }


# =============================================================================
# ZAPIER ENTRY POINT
# =============================================================================

# Determine data source: GitHub (default) or JSON input (fallback)
repo_url = input_data.get("repo_url", "").strip() if input_data else ""

try:
    if repo_url:
        data = fetch_from_github(repo_url)
    elif input_data and input_data.get("workflows", "").strip().startswith("["):
        # JSON mode: data passed as JSON strings from Google Sheets
        data = parse_input_json(input_data)
    else:
        # Default: fetch from GitHub
        data = fetch_from_github()
except Exception as e:
    # If fetch fails, set error output and exit
    output = {
        "insights_count": "0",
        "insights_json": "[]",
        "slack_message": f":x: Data fetch failed: {str(e)}",
        "has_insights": "false",
        "error": str(e),
    }
    # Early exit: skip pipeline if data fetch failed
    data = None

if data:
    # Run the full pipeline
    result = build_insights(
        data["workflows"],
        data["runs"],
        data["run_steps"],
        data["audit_events"],
        data["external_status"],
    )

    # Format for Slack (legacy single-message format)
    slack_message = format_all_insights(result, total_workflows=len(data["workflows"]))

    # Format three-layer output
    insights = result.get("insights", [])
    total_wf = len(data["workflows"])

    if insights:
        worst = insights[0]  # Already sorted by score (worst first)
        watch_list = [i for i in insights[1:] if i["status"] == "watch"]
        ambient_card = format_ambient_card(worst, watch_count=len(watch_list), total_workflows=total_wf)
        detail_thread = format_detail_thread(worst, watch_insights=watch_list)
    else:
        ambient_card = format_ambient_card(None, total_workflows=total_wf)
        detail_thread = ""

    # Set output for next Zapier step
    output = {
        "insights_count": str(result["insights_count"]),
        "insights_json": json.dumps(result["insights"]),
        "ambient_card": ambient_card,
        "detail_thread": detail_thread,
        "slack_message": slack_message,
        "has_insights": "true" if result["insights_count"] > 0 else "false",
    }
