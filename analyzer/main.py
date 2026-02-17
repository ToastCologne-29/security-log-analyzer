import argparse
import json
from pathlib import Path
from .parsers import parse_auth_log_line


def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to auth log file")
    parser.add_argument("--out", required=True, help="Path to output JSON report")

    args = parser.parse_args()
    log_path = Path(args.log)
    out_path = Path(args.out)

    if not log_path.exists():
        print(f"[!] Log file not found: {log_path}")
        return

    print("\n=== Security Log Analyzer Report ===\n")

    failed = 0
    success = 0
    failed_by_ip = {}

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event_type, ip = parse_auth_log_line(line)

            if event_type == "failed":
                failed += 1
                print("[!] Failed Login Detected")
                if ip:
                    failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

            elif event_type == "success":
                success += 1
                print("[+] Successful Login")

    print("\nSummary:")
    print(f"Failed logins: {failed}")
    print(f"Successful logins: {success}")

    brute_force_hits = []
    if failed_by_ip:
        print("\nFailed logins by IP:")
        for ip, count in sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip}: {count}")
            if count >= 5:
                brute_force_hits.append({"ip": ip, "failed_attempts": count})

    for hit in brute_force_hits:
        print(f"\n[HIGH] Possible brute-force from {hit['ip']} ({hit['failed_attempts']} failed attempts)")

    # Write JSON report
    report_data = {
        "log_file": str(log_path),
        "failed_logins": failed,
        "successful_logins": success,
        "failed_by_ip": failed_by_ip,
        "bruteforce_suspected": brute_force_hits,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    print(f"\nSaved report to: {out_path}\n")


if __name__ == "__main__":
    main()