from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_SPECS = (
    ("authentication_logs.csv", "event_type", "auth"),
    ("application_usage_logs.csv", "application", "app"),
    ("command_execution_logs.csv", "command", "cmd"),
    ("endpoint_activity_logs.csv", "action", "endpoint"),
    ("file_access_logs.csv", "action", "file"),
    ("network_access_logs.csv", "destination_domain", "net"),
)


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_user_key(raw_user_id: str, raw_username: str) -> str:
    user_id = clean_text(raw_user_id).upper()
    username = clean_text(raw_username).lower()
    if user_id:
        return user_id
    if username:
        return f"USER:{username}"
    return ""


def parse_timestamp(value: str) -> datetime | None:
    candidate = clean_text(value)
    if not candidate:
        return None
    try:
        return datetime.strptime(candidate, TIMESTAMP_FORMAT)
    except ValueError:
        return None


def parse_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [dict(row) for row in reader]


def normalize_action(namespace: str, value: str) -> str:
    action = clean_text(value)
    if not action:
        return "UNKNOWN"
    action = action.replace("\t", " ")
    action = " ".join(action.split())
    if namespace in {"auth", "endpoint", "file"}:
        action = action.upper()
    else:
        action = action.lower()
    return f"{namespace}:{action}"


def time_to_minutes(value: Any) -> int | None:
    candidate = clean_text(value)
    if not candidate:
        return None
    try:
        time_obj = datetime.strptime(candidate, "%H:%M")
        return time_obj.hour * 60 + time_obj.minute
    except ValueError:
        return None


def format_minutes(value: int) -> str:
    hours, minutes = divmod(max(0, value), 60)
    return f"{hours:02d}:{minutes:02d}"


def mean_or_zero(values: list[int]) -> float:
    return sum(values) / len(values) if values else 0.0


def load_baseline(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def score_severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def collect_user_activity(sample_dir: Path, target_day: str | None = None) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "daily_total": defaultdict(int),
            "action_counts": Counter(),
            "login_times": [],
            "command_counts": Counter(),
            "domain_counts": Counter(),
        }
    )

    for filename, _, namespace in LOG_SPECS:
        log_path = sample_dir / filename
        if not log_path.exists():
            continue

        for row in parse_csv(log_path):
            user_key = normalize_user_key(row.get("user_id", ""), row.get("username", ""))
            timestamp = parse_timestamp(row.get("timestamp", ""))
            if not user_key or timestamp is None:
                continue

            day_key = timestamp.date().isoformat()
            if target_day and day_key != target_day:
                continue

            current = summary[user_key]
            current["daily_total"][day_key] += 1

            if filename == "authentication_logs.csv":
                event_type = clean_text(row.get("event_type", "")).upper()
                status = clean_text(row.get("status", "")).upper()
                if event_type == "LOGIN" and status == "SUCCESS":
                    current["login_times"].append(timestamp.hour * 60 + timestamp.minute)

            action_field = row.get("action_field")
            if filename == "application_usage_logs.csv":
                action_field = row.get("application", "")
            elif filename == "command_execution_logs.csv":
                action_field = row.get("command", "")
            elif filename == "endpoint_activity_logs.csv":
                action_field = row.get("action", "")
            elif filename == "file_access_logs.csv":
                action_field = row.get("action", "")
            elif filename == "network_access_logs.csv":
                action_field = row.get("destination_domain", "")

            normalized_action = normalize_action(namespace, action_field)
            current["action_counts"][normalized_action] += 1

            if filename == "command_execution_logs.csv":
                current["command_counts"][normalize_action("cmd", row.get("command", ""))] += 1
            if filename == "network_access_logs.csv":
                current["domain_counts"][normalize_action("net", row.get("destination_domain", ""))] += 1

    return summary


def detect_anomalies(sample_dir: Path, baseline_path: Path, target_day: str | None = None) -> list[dict[str, Any]]:
    baseline = load_baseline(baseline_path)
    profiles = {profile["user_id"]: profile for profile in baseline.get("profiles", [])}
    activity = collect_user_activity(sample_dir, target_day)

    results: list[dict[str, Any]] = []

    suspicious_commands = {
        "cmd:systeminfo",
        "cmd:whoami",
        "cmd:netstat",
        "cmd:ipconfig",
        "cmd:ping",
        "cmd:git pull",
        "cmd:chmod",
        "cmd:curl",
        "cmd:dir",
        "cmd:ls -la",
        "cmd:top",
        "cmd:cat readme.txt",
    }

    for user_key, user_activity in sorted(activity.items()):
        profile = profiles.get(user_key)
        if profile is None:
            continue

        reasons: list[str] = []
        score = 0.0

        daily_totals = list(user_activity["daily_total"].values())
        if daily_totals:
            daily_total = sum(daily_totals)
            baseline_daily = profile.get("action_frequency_baseline", {})
            avg_actions = float(baseline_daily.get("avg_actions_per_day", 0) or 0)
            min_actions = baseline_daily.get("min_actions_per_day", 0) or 0
            max_actions = max(baseline_daily.get("max_actions_per_day", 0) or 0, int(avg_actions * 2))
            if daily_total < min_actions or daily_total > max_actions:
                reasons.append(
                    f"daily activity {daily_total} is outside the normal range {min_actions}-{max_actions}"
                )
                score += 25

        login_window = profile.get("login_baseline", {}).get("typical_first_login_window", {})
        low_minutes = time_to_minutes(login_window.get("p10"))
        high_minutes = time_to_minutes(login_window.get("p90"))
        for login_time in user_activity["login_times"]:
            if low_minutes is not None and high_minutes is not None and (login_time < low_minutes or login_time > high_minutes):
                reasons.append(
                    f"login at {format_minutes(login_time)} is outside the normal window {format_minutes(low_minutes)}-{format_minutes(high_minutes)}"
                )
                score += 30

        action_profile = profile.get("action_type_baseline", {}).get("top_actions", [])
        normal_actions = {item["action"] for item in action_profile}
        total_actions = sum(user_activity["action_counts"].values())
        if total_actions:
            for action_name, count in user_activity["action_counts"].most_common():
                if action_name in normal_actions:
                    continue
                ratio = count / total_actions
                if ratio >= 0.15:
                    reasons.append(f"unusual action type {action_name} appears {count} times ({ratio:.0%})")
                    score += 25

        for command_name, count in user_activity["command_counts"].items():
            if command_name in suspicious_commands:
                reasons.append(f"suspicious command {command_name} observed {count} time(s)")
                score += 25

        known_network_domains = {item["action"] for item in action_profile if item["action"].startswith("net:")}
        for domain_name, count in user_activity["domain_counts"].items():
            if domain_name not in known_network_domains:
                reasons.append(f"new destination {domain_name} contacted {count} time(s)")
                score += 20

        if not reasons:
            continue

        final_score = min(score, 100)
        results.append(
            {
                "user_id": user_key,
                "username": profile.get("username", ""),
                "date": target_day or "all_days",
                "risk_score": round(final_score, 1),
                "severity": score_severity(final_score),
                "reasons": reasons,
            }
        )

    return sorted(results, key=lambda item: item["risk_score"], reverse=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare log activity against the normal baseline and flag anomalies."
    )
    parser.add_argument(
        "--input-dir",
        default="sample",
        help="Directory containing the CSV log files (default: sample)",
    )
    parser.add_argument(
        "--baseline",
        default="baseline_profile.json",
        help="Baseline JSON generated by baseline.py (default: baseline_profile.json)",
    )
    parser.add_argument(
        "--date",
        default=None,
        help="Optional date to inspect, format YYYY-MM-DD, for example 2026-06-01",
    )
    args = parser.parse_args()

    sample_dir = Path(args.input_dir)
    if not sample_dir.exists() or not sample_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {sample_dir}")

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    anomalies = detect_anomalies(sample_dir, baseline_path, args.date)
    if not anomalies:
        print("No anomalous behavior detected for the selected period.")
        return

    print(json.dumps({"anomaly_count": len(anomalies), "anomalies": anomalies}, indent=2))


if __name__ == "__main__":
    main()
