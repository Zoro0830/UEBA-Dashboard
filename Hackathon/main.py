import subprocess
import sys


print("=" * 60)
print("UEBA INSIDER THREAT DETECTION SYSTEM")
print("=" * 60)

print("\n[1/3] Building baseline...")

result = subprocess.run(
    [sys.executable, "baseline.py"],
    capture_output=True,
    text=True
)

print(result.stdout)

if result.returncode != 0:
    print(result.stderr)
    sys.exit(1)

print("\n[2/3] Running detection...")

result = subprocess.run(
    [sys.executable, "detection.py"],
    capture_output=True,
    text=True
)

print(result.stdout)

if result.returncode != 0:
    print(result.stderr)
    sys.exit(1)

print("\n[3/3] Starting dashboard...")

subprocess.run(
    [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "dashboard.py"
    ]
)
