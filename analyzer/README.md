# Security Log Analyzer

A Python-based CLI tool that analyzes authentication logs to detect suspicious login activity and possible brute-force attacks.

## Features

- Parses authentication log files
- Detects failed and successful login attempts
- Aggregates failed logins by IP
- Identifies potential brute-force attacks
- Outputs structured JSON report

## Usage

```bash
python3 -m analyzer.main --log samples/sample_auth.log --out output/report.json