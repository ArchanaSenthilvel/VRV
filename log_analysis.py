import re
import csv
from collections import Counter

LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

FAILED_LOGIN_THRESHOLD = 10


def extract_data_from_logs(log_file):
    """Extract data for analysis from the log file."""
    ip_count = Counter()
    endpoint_count = Counter()
    failed_logins = Counter()

    with open(log_file, 'r') as logs:
        for line in logs:
            ip = extract_ip(line)
            if ip:
                ip_count[ip] += 1
            endpoint = extract_endpoint(line)
            if endpoint:
                endpoint_count[endpoint] += 1

            if is_failed_login(line):
                failed_logins[ip] += 1

    return ip_count, endpoint_count, failed_logins


def extract_ip(line):
    """Extract the IP address from a log entry."""
    match = re.match(r'^([\d\.]+)', line)
    return match.group(1) if match else None


def extract_endpoint(line):
    """Extract the endpoint from a log entry."""
    match = re.search(r'"(?:GET|POST|PUT|DELETE) (.*?) HTTP', line)
    return match.group(1) if match else None


def is_failed_login(line):
    """Determine if a log entry indicates a failed login attempt."""
    return '401' in line or "Invalid credentials" in line


def save_to_csv(ip_count, most_accessed_endpoint, flagged_ips):
    """Save the analysis results to a CSV file."""
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Requests Per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_count.most_common():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in flagged_ips:
            writer.writerow([ip, count])


def analyze_logs(log_file):
    """Analyze the logs and display/save the results."""
    ip_count, endpoint_count, failed_logins = extract_data_from_logs(log_file)

    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1])

    flagged_ips = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    print("Requests Per IP:")
    for ip, count in ip_count.most_common():
        print(f"{ip} -> {count} requests")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} -> Accessed {most_accessed_endpoint[1]} times")

    print("\nSuspicious Activity Detected:")
    if flagged_ips:
        for ip, count in flagged_ips:
            print(f"{ip} -> {count} failed login attempts")
    else:
        print("No suspicious activity detected.")
    save_to_csv(ip_count, most_accessed_endpoint, flagged_ips)
    print(f"\nResults saved to {OUTPUT_CSV}.")


if __name__ == "__main__":
    analyze_logs(LOG_FILE)
