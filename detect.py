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

    window_48h_start = analysis_end - timedelta(hours=48)
    baseline_start = analysis_end - timedelta(days=7)

    recent_runs = [r for r in runs if _parse_ts(r["started_at"]) >= window_48h_start]
    baseline_runs = [
        r for r in runs
        if baseline_start <= _parse_ts(r["started_at"]) < window_48h_start
    ]

    if not baseline_runs:
        return []

    recent_days = 2
    baseline_days = max(1, (window_48h_start - baseline_start).days)

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
        return [{
            "type": "silent_failure",
            "detail": (
                f"Volume dropped from ~{reference_volume:.0f}/day to "
                f"~{recent_volume_per_day:.0f}/day "
                f"(success rate {recent_success_rate:.0%}). "
                f"Possible trigger break or upstream event suppression."
            ),
            "metrics": {
                "reference_volume_per_day": round(reference_volume, 1),
                "recent_volume_per_day": round(recent_volume_per_day, 1),
                "volume_ratio": round(volume_ratio, 3),
                "recent_success_rate": round(recent_success_rate, 4),
            },
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

            span_minutes = (
                _parse_ts(last_failure["started_at"]) - _parse_ts(first_failure["started_at"])
            ).total_seconds() / 60

            failed_steps = set(
                r.get("failed_step_id", "") for r in auth_failures
                if r.get("failed_step_id")
            )

            detections.append({
                "type": "audit_correlation",
                "detail": (
                    f"{len(auth_failures)} {auth_failures[0]['error_category']} failures "
                    f"within {span_minutes:.0f}min of credential rotation"
                    f"{' at step ' + ', '.join(failed_steps) if failed_steps else ''}."
                ),
                "metrics": {
                    "audit_event_type": event["event_type"],
                    "audit_timestamp": event["timestamp"],
                    "auth_failure_count": len(auth_failures),
                    "failure_window_minutes": round(span_minutes, 1),
                    "error_categories": list(set(r["error_category"] for r in auth_failures)),
                    "failed_steps": list(failed_steps),
                },
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

            baseline_start = degraded_start - timedelta(days=7)
            baseline_runs = [
                r for r in wf_runs
                if baseline_start <= _parse_ts(r["started_at"]) < degraded_start
            ]

            if not during_runs or not baseline_runs:
                continue

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

            detections.append({
                "type": "provider_anomaly",
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
                },
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
    "at_risk": "At Risk",
    "watch": "Watch",
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
        window = metrics.get("failure_window_minutes", 0)
        if ts and count:
            ts_short = ts[:16].replace("T", " ")
            return f"{count} failures within {window:.0f}min of credential change at {ts_short}"

    if signal == "external_incident":
        affected = metrics.get("affected_workflows", [])
        provider = metrics.get("provider", "")
        start = metrics.get("degradation_start", "")
        end = metrics.get("degradation_end", "")
        total_timeouts = metrics.get("total_timeouts", 0)
        if start and end:
            s = start[11:16]
            e = end[11:16]
            parts = [f"{provider} degradation {s}-{e}"]
            if total_timeouts:
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

    # Format for Slack
    slack_message = format_all_insights(result, total_workflows=len(data["workflows"]))

    # Set output for next Zapier step
    output = {
        "insights_count": str(result["insights_count"]),
        "insights_json": json.dumps(result["insights"]),
        "slack_message": slack_message,
        "has_insights": "true" if result["insights_count"] > 0 else "false",
    }
