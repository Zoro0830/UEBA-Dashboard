import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

SAMPLE_DIR = Path("sample")
BASELINE_FILE = "baseline_profile.json"
RESULT_FILE = "detection_results.json"


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def read_csv(filename):
    path = SAMPLE_DIR / filename

    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def get_user(row):
    return clean(row.get("user_id")).upper()


def parse_time(value):
    try:
        return datetime.strptime(
            clean(value),
            "%Y-%m-%d %H:%M:%S"
        )
    except:
        return None


def load_baseline():
    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        data = json.load(file)

    return data["profiles"]


def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NORMAL"


def add_reason(reasons, category, points, message):
    reasons.append({
        "category": category,
        "points": points,
        "message": message
    })


def detect():
    baseline = load_baseline()

    if not isinstance(baseline, dict):
        baseline = {
            user["user_id"]: user
            for user in baseline
        }

    results = {}

    for user_id, user in baseline.items():
        results[user_id] = {
            "user_id": user_id,
            "username": user.get("username", ""),
            "full_name": user.get("full_name", ""),
            "department": user.get("department", ""),
            "role": user.get("role", ""),
            "privilege_level": user.get("privilege_level", ""),
            "reasons": [],
            "category_scores": {},
            "score": 0
        }

    failed_logins = Counter()
    unusual_logins = defaultdict(list)

    applications = defaultdict(Counter)
    unusual_applications = defaultdict(Counter)

    commands = defaultdict(Counter)
    suspicious_commands = defaultdict(Counter)

    sensitive_files = Counter()
    sensitive_downloads = Counter()
    file_events = Counter()
    large_downloads = Counter()

    external_bytes = Counter()
    external_connections = Counter()

    suspicious_patterns = [
        "vssadmin",
        "delete shadows",
        "mimikatz",
        "powershell -enc",
        "powershell -encodedcommand",
        "disable firewall",
        "set allprofiles state off",
        "bcdedit",
        "wevtutil",
        "net user",
        "net localgroup"
    ]

    for row in read_csv("authentication_logs.csv"):
        user_id = get_user(row)

        if user_id not in results:
            continue

        status = clean(
            row.get("status")
        ).upper()

        if status == "FAILURE":
            failed_logins[user_id] += 1

        if status != "SUCCESS":
            continue

        timestamp = parse_time(
            row.get("timestamp")
        )

        if timestamp is None:
            continue

        login_baseline = baseline[user_id].get(
            "login_baseline",
            {}
        )

        start = clean(
            login_baseline.get(
                "usual_login_start"
            )
        )

        end = clean(
            login_baseline.get(
                "usual_login_end"
            )
        )

        if start and end:
            try:
                start_hour = int(
                    start.split(":")[0]
                )

                end_hour = int(
                    end.split(":")[0]
                )

                if (
                    timestamp.hour < start_hour
                    or timestamp.hour > end_hour
                ):
                    unusual_logins[user_id].append(
                        timestamp.strftime("%H:%M")
                    )

            except:
                pass

    for row in read_csv("application_usage_logs.csv"):
        user_id = get_user(row)

        if user_id not in results:
            continue

        application = clean(
            row.get("application")
        )

        if not application:
            continue

        applications[user_id][application] += 1

        common_apps = baseline[user_id].get(
            "application_baseline",
            {}
        ).get(
            "common_applications",
            {}
        )

        if application not in common_apps:
            unusual_applications[user_id][application] += 1

    for row in read_csv("command_execution_logs.csv"):
        user_id = get_user(row)

        if user_id not in results:
            continue

        command = clean(
            row.get("command")
        )

        if not command:
            continue

        command = " ".join(command.split())

        commands[user_id][command] += 1

        command_lower = command.lower()

        for pattern in suspicious_patterns:
            if pattern in command_lower:
                suspicious_commands[user_id][command] += 1
                break

    for row in read_csv("file_access_logs.csv"):
        user_id = get_user(row)

        if user_id not in results:
            continue

        file_events[user_id] += 1

        sensitive = clean(
            row.get("is_sensitive_location")
        ).lower()

        action = clean(
            row.get("action")
        ).upper()

        if sensitive in ["true", "yes", "1"]:
            sensitive_files[user_id] += 1

            if action == "DOWNLOAD":
                sensitive_downloads[user_id] += 1

        if action == "DOWNLOAD":
            try:
                size = float(
                    clean(
                        row.get("file_size_kb")
                    ) or 0
                )
            except:
                size = 0

            if size >= 100 * 1024:
                large_downloads[user_id] += 1

    for row in read_csv("network_access_logs.csv"):
        user_id = get_user(row)

        if user_id not in results:
            continue

        destination_type = clean(
            row.get("destination_type")
        ).upper()

        if destination_type != "EXTERNAL":
            continue

        external_connections[user_id] += 1

        try:
            amount = float(
                clean(
                    row.get("bytes_transferred")
                ) or 0
            )
        except:
            amount = 0

        external_bytes[user_id] += amount

    for user_id in results:

        category_scores = {}
        reasons = []

        failed = failed_logins[user_id]

        if failed >= 10:
            category_scores["authentication"] = 20
            add_reason(
                reasons,
                "Authentication",
                20,
                f"High number of failed logins: {failed}"
            )

        elif failed >= 5:
            category_scores["authentication"] = 12
            add_reason(
                reasons,
                "Authentication",
                12,
                f"Repeated failed logins: {failed}"
            )

        elif failed >= 3:
            category_scores["authentication"] = 6
            add_reason(
                reasons,
                "Authentication",
                6,
                f"Multiple failed logins: {failed}"
            )

        unusual_login_count = len(
            unusual_logins[user_id]
        )

        if unusual_login_count >= 5:
            category_scores["login_time"] = 15
            add_reason(
                reasons,
                "Login Time",
                15,
                f"Repeated unusual login times: {unusual_login_count}"
            )

        elif unusual_login_count >= 2:
            category_scores["login_time"] = 8
            add_reason(
                reasons,
                "Login Time",
                8,
                f"Unusual login activity detected: {unusual_login_count} times"
            )

        unusual_apps = unusual_applications[user_id]

        repeated_apps = [
            (app, count)
            for app, count in unusual_apps.items()
            if count >= 3
        ]

        if repeated_apps:
            app, count = max(
                repeated_apps,
                key=lambda x: x[1]
            )

            if count >= 10:
                category_scores["application"] = 15
                add_reason(
                    reasons,
                    "Application",
                    15,
                    f"Repeated unusual application: {app} ({count} events)"
                )

            else:
                category_scores["application"] = 8
                add_reason(
                    reasons,
                    "Application",
                    8,
                    f"Unusual application used repeatedly: {app} ({count} events)"
                )

        suspicious = suspicious_commands[user_id]

        if suspicious:
            total_suspicious_commands = sum(
                suspicious.values()
            )

            if total_suspicious_commands >= 5:
                category_scores["commands"] = 30
                add_reason(
                    reasons,
                    "Command",
                    30,
                    f"Repeated suspicious commands: {total_suspicious_commands}"
                )

            else:
                category_scores["commands"] = 20
                command = max(
                    suspicious,
                    key=suspicious.get
                )

                add_reason(
                    reasons,
                    "Command",
                    20,
                    f"Suspicious command detected: {command}"
                )

        sensitive = sensitive_files[user_id]
        downloads = sensitive_downloads[user_id]
        large = large_downloads[user_id]

        file_score = 0

        if downloads >= 5:
            file_score += 25
            add_reason(
                reasons,
                "File Access",
                25,
                f"Repeated sensitive file downloads: {downloads}"
            )

        elif downloads >= 2:
            file_score += 15
            add_reason(
                reasons,
                "File Access",
                15,
                f"Multiple sensitive file downloads: {downloads}"
            )

        elif sensitive >= 5:
            file_score += 10
            add_reason(
                reasons,
                "File Access",
                10,
                f"Repeated sensitive file access: {sensitive}"
            )

        if large >= 3:
            file_score += 10
            add_reason(
                reasons,
                "File Access",
                10,
                f"Multiple large file downloads: {large}"
            )

        if file_score > 0:
            category_scores["file_access"] = min(
                file_score,
                30
            )

        total_external_mb = (
            external_bytes[user_id] /
            (1024 * 1024)
        )

        network_score = 0

        if total_external_mb >= 500:
            network_score = 30
            add_reason(
                reasons,
                "Network",
                30,
                f"Very large external transfer: {total_external_mb:.1f} MB"
            )

        elif total_external_mb >= 100:
            network_score = 20
            add_reason(
                reasons,
                "Network",
                20,
                f"Large external transfer: {total_external_mb:.1f} MB"
            )

        elif external_connections[user_id] >= 50:
            network_score = 8
            add_reason(
                reasons,
                "Network",
                8,
                f"High number of external connections: {external_connections[user_id]}"
            )

        if network_score > 0:
            category_scores["network"] = network_score

        total_score = sum(
            category_scores.values()
        )

        try:
            privilege = int(
                results[user_id]["privilege_level"]
            )
        except:
            privilege = 0

        if privilege >= 4 and total_score >= 30:
            total_score = int(
                total_score * 1.15
            )

        elif privilege >= 3 and total_score >= 30:
            total_score = int(
                total_score * 1.08
            )

        total_score = min(
            total_score,
            100
        )

        results[user_id]["score"] = total_score
        results[user_id]["category_scores"] = category_scores
        results[user_id]["reasons"] = reasons

    final_results = []

    for user_id, result in results.items():

        score = result["score"]

        final_results.append({
            "user_id": result["user_id"],
            "username": result["username"],
            "full_name": result["full_name"],
            "department": result["department"],
            "role": result["role"],
            "privilege_level": result["privilege_level"],
            "risk_score": score,
            "risk_level": get_risk_level(score),
            "anomaly_count": len(result["reasons"]),
            "reasons": [
                reason["message"]
                for reason in result["reasons"]
            ],
            "category_scores": result["category_scores"]
        })

    final_results.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )

    return final_results


def main():

    print("=" * 60)
    print("UEBA INSIDER THREAT DETECTION")
    print("=" * 60)

    try:
        results = detect()

        with open(
            RESULT_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                results,
                file,
                indent=4
            )

        print()

        for user in results:

            if user["risk_score"] == 0:
                continue

            print(
                f"{user['username']:<25} "
                f"{user['risk_score']:>3} "
                f"{user['risk_level']:<10} "
                f"{user['anomaly_count']} anomalies"
            )

        print()
        print(
            f"Results saved to {RESULT_FILE}"
        )

    except Exception as error:

        print()
        print(
            f"Detection error: {error}"
        )


if __name__ == "__main__":
    main()
