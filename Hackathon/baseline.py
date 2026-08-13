from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, pstdev
from typing import Any


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True)
class LogSpec:
	filename: str
	action_field: str
	action_namespace: str


LOG_SPECS = (
	LogSpec("authentication_logs.csv", "event_type", "auth"),
	LogSpec("application_usage_logs.csv", "application", "app"),
	LogSpec("command_execution_logs.csv", "command", "cmd"),
	LogSpec("endpoint_activity_logs.csv", "action", "endpoint"),
	LogSpec("file_access_logs.csv", "action", "file"),
	LogSpec("network_access_logs.csv", "destination_domain", "net"),
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


def percentile(sorted_values: list[float], pct: float) -> float:
	if not sorted_values:
		return 0.0
	if pct <= 0:
		return sorted_values[0]
	if pct >= 100:
		return sorted_values[-1]
	index = (len(sorted_values) - 1) * (pct / 100)
	lower = int(index)
	upper = min(lower + 1, len(sorted_values) - 1)
	if lower == upper:
		return sorted_values[lower]
	weight = index - lower
	return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def format_time_from_minutes(value: float) -> str:
	minutes = max(0, min(int(round(value)), 23 * 60 + 59))
	hour, minute = divmod(minutes, 60)
	return f"{hour:02d}:{minute:02d}"


def load_user_metadata(sample_dir: Path) -> dict[str, dict[str, str]]:
	users_path = sample_dir / "users.csv"
	if not users_path.exists():
		return {}

	metadata: dict[str, dict[str, str]] = {}
	for row in parse_csv(users_path):
		user_key = normalize_user_key(row.get("user_id", ""), row.get("username", ""))
		if not user_key:
			continue

		metadata[user_key] = {
			"user_id": clean_text(row.get("user_id", "")).upper(),
			"username": clean_text(row.get("username", "")).lower(),
			"full_name": clean_text(row.get("full_name", "")),
			"department": clean_text(row.get("department", "")).upper(),
			"role": clean_text(row.get("role", "")),
			"privilege_level": clean_text(row.get("privilege_level", "")),
			"office_location": clean_text(row.get("office_location", "")),
			"usual_login_start": clean_text(row.get("usual_login_start", "")),
			"usual_login_end": clean_text(row.get("usual_login_end", "")),
		}

	return metadata


def build_behavior_baseline(sample_dir: Path) -> dict[str, Any]:
	users = load_user_metadata(sample_dir)

	per_user_daily_actions: dict[str, Counter[str]] = defaultdict(Counter)
	per_user_action_types: dict[str, Counter[str]] = defaultdict(Counter)
	per_user_login_candidates: dict[str, dict[str, int]] = defaultdict(dict)

	rows_seen = 0
	rows_used = 0

	for spec in LOG_SPECS:
		log_path = sample_dir / spec.filename
		if not log_path.exists():
			continue

		for row in parse_csv(log_path):
			rows_seen += 1
			user_key = normalize_user_key(row.get("user_id", ""), row.get("username", ""))
			timestamp = parse_timestamp(row.get("timestamp", ""))
			if not user_key or timestamp is None:
				continue

			rows_used += 1
			day_key = timestamp.date().isoformat()
			per_user_daily_actions[user_key][day_key] += 1

			action_label = normalize_action(spec.action_namespace, row.get(spec.action_field, ""))
			per_user_action_types[user_key][action_label] += 1

			if spec.filename == "authentication_logs.csv":
				event_type = clean_text(row.get("event_type", "")).upper()
				status = clean_text(row.get("status", "")).upper()
				if event_type == "LOGIN" and status == "SUCCESS":
					minutes = timestamp.hour * 60 + timestamp.minute
					existing = per_user_login_candidates[user_key].get(day_key)
					if existing is None or minutes < existing:
						per_user_login_candidates[user_key][day_key] = minutes

	user_keys = sorted(set(users) | set(per_user_daily_actions) | set(per_user_action_types))
	user_profiles: list[dict[str, Any]] = []

	for user_key in user_keys:
		metadata = users.get(user_key, {})
		daily_counts = per_user_daily_actions.get(user_key, Counter())
		action_counter = per_user_action_types.get(user_key, Counter())
		login_minutes = sorted(per_user_login_candidates.get(user_key, {}).values())

		daily_values = list(daily_counts.values())
		total_actions = sum(daily_values)
		days_observed = len(daily_values)
		avg_actions = mean(daily_values) if daily_values else 0.0

		login_mean = mean(login_minutes) if login_minutes else 0.0
		login_std = pstdev(login_minutes) if len(login_minutes) > 1 else 0.0

		top_actions: list[dict[str, Any]] = []
		for action_name, count in action_counter.most_common(10):
			ratio = (count / total_actions) if total_actions else 0.0
			top_actions.append(
				{
					"action": action_name,
					"count": count,
					"ratio": round(ratio, 4),
				}
			)

		user_profiles.append(
			{
				"user_id": metadata.get("user_id", user_key),
				"username": metadata.get("username", ""),
				"full_name": metadata.get("full_name", ""),
				"department": metadata.get("department", ""),
				"role": metadata.get("role", ""),
				"privilege_level": metadata.get("privilege_level", ""),
				"office_location": metadata.get("office_location", ""),
				"usual_login_start": metadata.get("usual_login_start", ""),
				"usual_login_end": metadata.get("usual_login_end", ""),
				"observation_days": days_observed,
				"login_baseline": {
					"successful_login_days": len(login_minutes),
					"avg_first_login_time": format_time_from_minutes(login_mean),
					"stddev_first_login_minutes": round(login_std, 2),
					"typical_first_login_window": {
						"p10": format_time_from_minutes(percentile(login_minutes, 10)),
						"p90": format_time_from_minutes(percentile(login_minutes, 90)),
					},
				},
				"action_frequency_baseline": {
					"total_actions": total_actions,
					"avg_actions_per_day": round(avg_actions, 2),
					"min_actions_per_day": min(daily_values) if daily_values else 0,
					"max_actions_per_day": max(daily_values) if daily_values else 0,
				},
				"action_type_baseline": {
					"distinct_action_types": len(action_counter),
					"top_actions": top_actions,
				},
			}
		)

	return {
		"generated_at": datetime.now(UTC).strftime(TIMESTAMP_FORMAT),
		"source_directory": str(sample_dir),
		"rows_seen": rows_seen,
		"rows_used": rows_used,
		"users_profiled": len(user_profiles),
		"profile_type": "normal_user_behavior_baseline",
		"profiles": user_profiles,
	}


def write_baseline(output_path: Path, baseline: dict[str, Any]) -> None:
	output_path.parent.mkdir(parents=True, exist_ok=True)
	with output_path.open("w", encoding="utf-8") as handle:
		json.dump(baseline, handle, indent=2)


def main() -> None:
	parser = argparse.ArgumentParser(
		description=(
			"Build a baseline of normal user behavior from sample logs, including "
			"login times, action frequency, and action types."
		)
	)
	parser.add_argument(
		"--input-dir",
		default="sample",
		help="Directory containing source CSV files (default: sample)",
	)
	parser.add_argument(
		"--output",
		default="baseline_profile.json",
		help="Path to write generated baseline JSON (default: baseline_profile.json)",
	)
	args = parser.parse_args()

	sample_dir = Path(args.input_dir)
	if not sample_dir.exists() or not sample_dir.is_dir():
		raise FileNotFoundError(f"Input directory not found: {sample_dir}")

	baseline = build_behavior_baseline(sample_dir)
	output_path = Path(args.output)
	write_baseline(output_path, baseline)

	print(f"Baseline generated for {baseline['users_profiled']} users.")
	print(f"Rows used: {baseline['rows_used']} / {baseline['rows_seen']}")
	print(f"Output: {output_path}")


if __name__ == "__main__":
	main()
