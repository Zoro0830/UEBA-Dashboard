import csv
import json
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path



SAMPLE_DIR = Path("sample")
OUTPUT_FILE = "baseline_profile.json"



def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def read_csv(filename):
    path = SAMPLE_DIR / filename

    if not path.exists():
        print(f"Warning: {filename} not found")
        return []

    with open(path, "r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def get_user(row):
    return clean(row.get("user_id")).upper()


def parse_time(timestamp):
    try:
        return datetime.strptime(
            clean(timestamp),
            "%Y-%m-%d %H:%M:%S"
        )
    except:
        return None



def load_users():
    users = {}

    for row in read_csv("users.csv"):

        user_id = get_user(row)

        if not user_id:
            continue

        users[user_id] = {
            "user_id": user_id,
            "username": clean(row.get("username")),
            "full_name": clean(row.get("full_name")),
            "department": clean(row.get("department")),
            "role": clean(row.get("role")),
            "privilege_level": clean(row.get("privilege_level")),
            "office_location": clean(row.get("office_location")),
            "usual_login_start": clean(row.get("usual_login_start")),
            "usual_login_end": clean(row.get("usual_login_end"))
        }

    return users



def build_baseline():

    users = load_users()

    # Create storage for every user
    profiles = {}

    for user_id, info in users.items():

        profiles[user_id] = {
            **info,

            # Login
            "login_hours": [],

            # Applications
            "applications": Counter(),

            # Commands
            "commands": Counter(),

            # Files
            "files": Counter(),
            "file_actions": Counter(),
            "sensitive_files": 0,

            # Network
            "network_destinations": Counter(),
            "external_connections": 0,
            "network_bytes": 0,

            # Endpoint
            "processes": Counter(),
            "endpoint_actions": Counter()
        }


    
    auth_logs = read_csv("authentication_logs.csv")

    for row in auth_logs:

        user_id = get_user(row)

        if user_id not in profiles:
            continue

        status = clean(row.get("status")).upper()
        event_type = clean(row.get("event_type")).upper()

        # Only successful logins are used for normal login baseline
        if event_type == "LOGIN" and status == "SUCCESS":

            timestamp = parse_time(row.get("timestamp"))

            if timestamp:
                profiles[user_id]["login_hours"].append(
                    timestamp.hour
                )


    
    app_logs = read_csv("application_usage_logs.csv")

    for row in app_logs:

        user_id = get_user(row)

        if user_id not in profiles:
            continue

        application = clean(row.get("application"))

        if application:
            profiles[user_id]["applications"][application] += 1


   
    command_logs = read_csv("command_execution_logs.csv")

    for row in command_logs:

        user_id = get_user(row)

        if user_id not in profiles:
            continue

        command = clean(row.get("command"))

        if command:

            # Normalize whitespace
            command = " ".join(command.split())

            profiles[user_id]["commands"][command] += 1


   
    file_logs = read_csv("file_access_logs.csv")

    for row in file_logs:

        user_id = get_user(row)

        if user_id not in profiles:
            continue

        file_path = clean(row.get("file_path"))
        action = clean(row.get("action")).upper()

        if file_path:
            profiles[user_id]["files"][file_path] += 1

        if action:
            profiles[user_id]["file_actions"][action] += 1

        sensitive = clean(
            row.get("is_sensitive_location")
        ).lower()

        if sensitive in ["true", "1", "yes"]:
            profiles[user_id]["sensitive_files"] += 1


   
    network_logs = read_csv("network_access_logs.csv")

    for row in network_logs:

        user_id = get_user(row)

        if user_id not in profiles:
            continue

        domain = clean(row.get("destination_domain"))

        if domain:
            profiles[user_id]["network_destinations"][domain] += 1

        destination_type = clean(
            row.get("destination_type")
        ).upper()

        if destination_type == "EXTERNAL":
            profiles[user_id]["external_connections"] += 1

        try:
            bytes_transferred = float(
                clean(row.get("bytes_transferred")) or 0
            )
        except:
            bytes_transferred = 0

        profiles[user_id]["network_bytes"] += bytes_transferred


    endpoint_logs = read_csv("endpoint_activity_logs.csv")

    for row in endpoint_logs:

        user_id = get_user(row)

        if user_id not in profiles:
            continue

        process = clean(row.get("process_name"))
        action = clean(row.get("action"))

        if process:
            profiles[user_id]["processes"][process] += 1

        if action:
            profiles[user_id]["endpoint_actions"][action] += 1


   
    final_profiles = {}

    for user_id, profile in profiles.items():

        login_hours = profile["login_hours"]

        if login_hours:

            common_login_hour = Counter(
                login_hours
            ).most_common(1)[0][0]

        else:
            common_login_hour = None


        final_profiles[user_id] = {

            "user_id": profile["user_id"],
            "username": profile["username"],
            "full_name": profile["full_name"],
            "department": profile["department"],
            "role": profile["role"],
            "privilege_level": profile["privilege_level"],
            "office_location": profile["office_location"],

            # Login baseline
            "login_baseline": {
                "usual_login_start":
                    profile["usual_login_start"],

                "usual_login_end":
                    profile["usual_login_end"],

                "most_common_login_hour":
                    common_login_hour
            },

            
            "application_baseline": {
                "common_applications":
                    dict(
                        profile["applications"].most_common(10)
                    )
            },

            "command_baseline": {
                "common_commands":
                    dict(
                        profile["commands"].most_common(10)
                    )
            },

            "file_baseline": {
                "common_files":
                    dict(
                        profile["files"].most_common(10)
                    ),

                "file_actions":
                    dict(profile["file_actions"]),

                "sensitive_file_access":
                    profile["sensitive_files"]
            },

            "network_baseline": {
                "common_destinations":
                    dict(
                        profile[
                            "network_destinations"
                        ].most_common(10)
                    ),

                "external_connections":
                    profile["external_connections"],

                "total_bytes":
                    profile["network_bytes"]
            },

            "endpoint_baseline": {
                "common_processes":
                    dict(
                        profile["processes"].most_common(10)
                    ),

                "common_actions":
                    dict(profile["endpoint_actions"])
            }
        }


    return final_profiles

def main():

    print("=" * 60)
    print("UEBA USER BEHAVIOR BASELINE")
    print("=" * 60)

    profiles = build_baseline()

    output = {
        "generated_at":
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "users_profiled":
            len(profiles),

        "profiles":
            profiles
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print()
    print(f"Users profiled: {len(profiles)}")
    print(f"Baseline saved: {OUTPUT_FILE}")
    print()

    # Show a small example
    for user_id, profile in list(
        profiles.items()
    )[:3]:

        print("-" * 60)

        print(
            f"{profile['username']} "
            f"({user_id})"
        )

        print(
            "Normal login:",
            profile["login_baseline"]
        )

        print(
            "Common applications:",
            list(
                profile[
                    "application_baseline"
                ]["common_applications"]
                .keys()
            )[:5]
        )

        print(
            "Common commands:",
            list(
                profile[
                    "command_baseline"
                ]["common_commands"]
                .keys()
            )[:5]
        )


if __name__ == "__main__":
    main()
