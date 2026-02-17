# Security Log Analyzer

A Python-based CLI tool that analyzes authentication logs to detect suspicious login activity and possible brute-force attacks.

## Features

- Parses authentication log files
- Detects failed and successful login attempts
- Aggregates failed logins by IP
- Identifies potential brute-force attacks
- Outputs structured JSON report

## Installation

Clone the repository:

```bash
git clone https://github.com/ToastCologne-29/security-log-analyzer.git
cd security-log-analyzer
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate virtual environment (Mac/Linux):

```bash
source venv/bin/activate
```

Install required dependencies:

```bash
pip install colorama
```

## Usage

```bash
python3 -m analyzer.main --log samples/sample_auth.log --out output/report.json

## Tech Stack

- Python 3
- CLI (argparse)
- JSON reporting
- Security log parsing
- Detection logic (brute-force analysis)

## Project Structure

security-log-analyzer/
│
├── analyzer/
│   ├── main.py
│   ├── parsers.py
│   ├── detections.py
│
├── samples/
│   └── sample_auth.log
│
├── output/
│   └── report.json
│
└── README.md

## Example Output

=== Security Log Analyzer Report ===

[!] Failed Login Detected
[+] Successful Login

Summary:
Failed logins: 5
Successful logins: 1

[HIGH] Possible brute-force from 203.0.113.10