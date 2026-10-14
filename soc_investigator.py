
from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("security.log")
REPORT_FILE = Path("investigation_report.txt")
FAILED_LOGIN_LIMIT = 3

def read_logs(file_path):
    events = []

    with file_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 3:
                print(f"Skipping malformed line {line_number}")
                continue

            details = {}

            for item in parts[3:]:
                if "=" in item:
                    key, value = item.split("=", 1)
                    details[key] = value

            required = {"user", "action", "ip"}

            if not required.issubset(details):
                print(f"Skipping incomplete line {line_number}")
                continue

            events.append({
                "timestamp": parts[0] + " " + parts[1],
                "level": parts[2],
                "user": details["user"],
                "action": details["action"],
                "ip": details["ip"]
            })

    return events

def investigate(events):
    failed_by_ip = defaultdict(int)
    successful_ips = set()

    for event in events:
        ip = event["ip"]

        if event["action"] == "login_failed":
            failed_by_ip[ip] += 1

        elif event["action"] == "login_success":
            successful_ips.add(ip)

    alerts = []

    for ip, count in failed_by_ip.items():
        if count < FAILED_LOGIN_LIMIT:
            continue

        if ip in successful_ips:
            severity = "HIGH"
            reason = (
                "Repeated failed attempts and a recorded "
                "successful login from the same IP"
            )
        else:
            severity = "MEDIUM"
            reason = "Repeated failed login attempts from the same IP"

        alerts.append({
            "ip": ip,
            "failed_attempts": count,
            "severity": severity,
            "reason": reason
        })

    return alerts

def save_report(events, alerts, file_path):
    with file_path.open("w", encoding="utf-8") as report:
        report.write("SOC ALERT INVESTIGATION REPORT\n")
        report.write("=" * 40 + "\n")
        report.write(f"Total events analyzed: {len(events)}\n")
        report.write(f"Alerts generated: {len(alerts)}\n\n")

        if not alerts:
            report.write("No alerts matched the configured rules.\n")

        for alert in alerts:
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"IP address: {alert['ip']}\n")
            report.write(
                f"Failed attempts: {alert['failed_attempts']}\n"
            )
            report.write(f"Finding: {alert['reason']}\n")
            report.write("-" * 40 + "\n")

def main():
    print("SOC ALERT INVESTIGATION TOOL")
    try:
        events = read_logs(LOG_FILE)
    except FileNotFoundError:
        print("ERROR: security.log was not found.")
        print("Keep security.log in the project folder.")
        return
    except OSError as error:
        print(f"ERROR reading log file: {error}")
        return

    alerts = investigate(events)

    print(f"\nTotal events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(f"\n[{alert['severity']}] Security alert")
        print("IP:", alert["ip"])
        print("Failed attempts:", alert["failed_attempts"])
        print("Finding:", alert["reason"])

    try:
        save_report(events, alerts, REPORT_FILE)
    except OSError as error:
        print(f"Could not save report: {error}")
        return

    print(f"\nReport saved: {REPORT_FILE}")
    print("Investigation completed.")


if __name__ == "__main__":
    main()
