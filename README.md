
# SOC Alert Investigation Tool
A beginner-friendly Python project for analyzing structured
security logs and detecting repeated failed login attempts.

## Features
- Reads structured security event logs
- Counts failed login attempts by IP address
- Generates alerts when an IP reaches the configured threshold
- Assigns HIGH or MEDIUM severity using simple rules
- Exports findings to a text investigation report
- Handles missing log files and incomplete log entries

## Technologies
- Python 3
- File handling
- Dictionaries and sets
- Log analysis
- Rule-based detection

## Files
- `security.log`: fictional sample events
- `soc_investigator.py`: main program
- `README.md`: project documentation
- `investigation_report.txt`: generated report
## Run
Open a terminal in the project directory and run:
    python soc_investigator.py

On Windows, this may also work:
    py soc_investigator.py

## Detection Rules
Three or more failed logins from one IP generate an alert.
If that IP also appears in successful login records, the alert
is marked HIGH. Otherwise, it is marked MEDIUM.

## Limitations
This is an educational demonstration, not a production SIEM.
It does not correlate events within a time window, verify IP
reputation, or prove account compromise. Results depend on
the input log format and configured detection threshold.

## Disclaimer
Use only authorized logs or fictional sample data.
This project is intended for defensive cybersecurity learning.