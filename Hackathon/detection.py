import csv
import json
from collections import Counter
from pathlib import Path
from datetime import datetime

SAMPLE_DIR = Path("sample")
BASELINE_FILE = "baseline_profile.json"
RESULT_FILE = "detection_results.json"


def clean(value):
    return "" if value is None else str(value).strip()


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
    return "LOW"


def add_anomaly(results, user_id, points, message):
    if user_id not in results:
        return

    results[user_id]["score"] += points
    results[user_id]["anomalies"].append(message)


def detect():
    profiles = load_baseline()

    if isinstance(profiles, dict):
        baseline = profiles
    else:
        baseline = {
            user["user_id"]: user
            for user in profiles
        }

    results = {}

    for user_id, user in baseline.items():
        results[user_id] = {
            "user_id": user.get("user_id", user_id),
            "username": user.get("username", ""),
            "full_name": user.get("full_name", ""),
            "department": user.get("department", ""),
            "role": user.get("role", ""),
            "privilege_level": user.get("privilege_level", ""),
            "score": 0,
            "anomalies": []
        }

    auth_logs = read_csv("authentication_logs.csv")
    failed_logins = Counter()

    for row in auth_logs:
        user_id = get_user(row)

        if user_id not in results:
            continue

        status = clean(row.get("status")).upper()

        if status == "FAILURE":
            failed_logins[user_id] += 1

        if status != "SUCCESS":
            continue

        timestamp = parse_time(row.get("timestamp"))

        if timestamp is None:
            continue

        login_baseline = baseline[user_id].get(
            "login_baseline",
            {}
        )

        start = clean(
            login_baseline.get("usual_login_start")
        )

        end = clean(
            login_baseline.get("usual_login_end")
        )

        if not start or not end:
            continue

        try:
            start_hour = int(start.split(":")[0])
            end_hour = int(end.split(":")[0])
            current_hour = timestamp.hour

            if current_hour < start_hour or current_hour > end_hour:
                add_anomaly(
                    results,
                    user_id,
                    10,
                    f"Unusual login time: {timestamp.strftime('%H:%M')}"
                )
        except:
            pass

    for user_id, count in failed_logins.items():
        if count >= 5:
            add_anomaly(
                results,
                user_id,
                15,
                f"Repeated failed logins: {count}"
            )
        elif count >= 3:
            add_anomaly(
                results,
                user_id,
                10,
                f"Multiple failed logins: {count}"
            )

    app_logs = read_csv("application_usage_logs.csv")

    for row in app_logs:
        user_id = get_user(row)

        if user_id not in results:
            continue

        application = clean(row.get("application"))

        if not application:
            continue

        common_apps = baseline[user_id].get(
            "application_baseline",
            {}
        ).get(
            "common_applications",
            {}
        )

        if application not in common_apps:
            add_anomaly(
                results,
                user_id,
                10,
                f"Unusual application: {application}"
            )

    command_logs = read_csv("command_execution_logs.csv")

    suspicious_patterns = [
        "vssadmin",
        "delete shadows",
        "net user",
        "net localgroup",
        "mimikatz",
        "powershell -enc",
        "powershell -encodedcommand",
        "disable firewall",
        "set allprofiles state off",
        "bcdedit",
        "reg add",
        "reg delete",
        "wevtutil"
    ]

    for row in command_logs:
        user_id = get_user(row)

        if user_id not in results:
            continue

        command = clean(row.get("command"))

        if not command:
            continue

        command_lower = command.lower()

        for pattern in suspicious_patterns:
            if pattern in command_lower:
                add_anomaly(
                    results,
                    user_id,
                    25,
                    f"Suspicious command: {command}"
                )
                break

        privilege = clean(
            row.get("privilege_used")
        ).upper()

        if privilege == "ADMIN":
            user_privilege = clean(
                baseline[user_id].get(
                    "privilege_level",
                    ""
                )
            )

            if user_privilege in ["", "1", "2"]:
                add_anomaly(
                    results,
                    user_id,
                    15,
                    "Unexpected ADMIN command usage"
                )

    file_logs = read_csv("file_access_logs.csv")
    file_counts = Counter()

    for row in file_logs:
        user_id = get_user(row)

        if user_id not in results:
            continue

        file_counts[user_id] += 1

        sensitive = clean(
            row.get("is_sensitive_location")
        ).lower()

        action = clean(
            row.get("action")
        ).upper()

        if sensitive in ["true", "yes", "1"]:
            add_anomaly(
                results,
                user_id,
                15,
                "Sensitive resource accessed"
            )

            if action == "DOWNLOAD":
                add_anomaly(
                    results,
                    user_id,
                    20,
                    "Sensitive resource downloaded"
                )

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
                add_anomaly(
                    results,
                    user_id,
                    15,
                    "Large file download"
                )

    for user_id, count in file_counts.items():
        if count >= 100:
            add_anomaly(
                results,
                user_id,
                15,
                f"Excessive file activity: {count} events"
            )

    network_logs = read_csv("network_access_logs.csv")
    external_bytes = Counter()

    for row in network_logs:
        user_id = get_user(row)

        if user_id not in results:
            continue

        destination_type = clean(
            row.get("destination_type")
        ).upper()

        if destination_type != "EXTERNAL":
            continue

        try:
            bytes_transferred = float(
                clean(
                    row.get("bytes_transferred")
                ) or 0
            )
        except:
            bytes_transferred = 0

        external_bytes[user_id] += bytes_transferred

    for user_id, total_bytes in external_bytes.items():
        if total_bytes >= 100 * 1024 * 1024:
            mb = round(
                total_bytes / (1024 * 1024),
                2
            )

            add_anomaly(
                results,
                user_id,
                25,
                f"Large external data transfer: {mb} MB"
            )

        if total_bytes >= 500 * 1024 * 1024:
            add_anomaly(
                results,
                user_id,
                15,
                "Very large external data transfer"
            )

    for user_id, result in results.items():
        try:
            privilege = int(
                result["privilege_level"]
            )
        except:
            privilege = 0

        if privilege >= 4:
            result["score"] += 5
        elif privilege >= 3:
            result["score"] += 3

    final_results = []

    for user_id, result in results.items():
        unique_anomalies = list(
            dict.fromkeys(
                result["anomalies"]
            )
        )

        score = min(
            int(result["score"]),
            100
        )

        final_results.append({
            "user_id": result["user_id"],
            "username": result["username"],
            "full_name": result["full_name"],
            "department": result["department"],
            "role": result["role"],
            "privilege_level": result["privilege_level"],
            "risk_score": score,
            "risk_level": get_risk_level(score),
            "anomaly_count": len(unique_anomalies),
            "reasons": unique_anomalies
        })

    final_results.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    return final_results


def main():
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

    print("=" * 60)
    print("UEBA INSIDER THREAT DETECTION")
    print("=" * 60)

    for user in results:
        if user["risk_score"] <= 0:
            continue

        print(
            f"{user['username']} | "
            f"{user['risk_score']} | "
            f"{user['risk_level']}"
        )

        for reason in user["reasons"][:5]:
            print(f" - {reason}")

    print("=" * 60)
    print(f"Results saved to {RESULT_FILE}")


if __name__ == "__main__":
    main()
