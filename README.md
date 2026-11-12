# SSH Log Analyzer

A Python tool that scans Linux SSH authentication logs (`auth.log`) and flags three common attack patterns: **brute-force attempts**, **username spraying**, and **possible account compromise**.

## Why I built this

SOC analysts review authentication logs every day to spot attacks early. I built this tool to practise the same detection logic used to write SIEM alerts in tools like Splunk: filter the events that matter, pull out the key fields, count them, and correlate them into alerts an analyst can act on.

## Features

| Detection | What it looks for | MITRE ATT&CK |
|---|---|---|
| **Brute force** | 5 or more failed logins from one IP | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| **Username spraying** | One IP trying 3 or more different usernames | [T1110.003 – Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Possible compromise** | A successful login from an IP already flagged for brute force | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) |

Thresholds are set at the top of the script and can be tuned to reduce false positives.

## Example output

![Example output](screenshots/output.png)

```
=== ALERTS ===
[BRUTE FORCE] 45.83.12.7 had 10 failed login attempts
[BRUTE FORCE] 103.27.44.91 had 6 failed login attempts
[USERNAME SPRAYING] 103.27.44.91 tried 6 different usernames: ftp, guest, oracle, postgres, test, ubuntu
[POSSIBLE COMPROMISE] 45.83.12.7 logged in as 'admin' at Nov 5 02:14:09 after 10 failed attempts
```

Legitimate users who mistyped their password once (`192.168.1.10`, `192.168.1.22`) are **not** flagged.

## How to run

Requires Python 3. No extra libraries are needed.

```bash
git clone https://github.com/YOUR-USERNAME/ssh-log-analyzer.git
cd ssh-log-analyzer
python3 analyzer.py              # scans the included sample auth.log
python3 analyzer.py /path/to/other.log   # scans any other SSH auth log
```

## How it works

1. **Parse:** reads the log line by line and keeps only `Failed password` events, extracting the source IP and the username tried.
2. **Count:** keeps a count of failures per IP and a set of the different usernames each IP tried.
3. **Detect:** raises an alert when an IP crosses the brute-force or spraying threshold.
4. **Correlate:** re-reads the log for `Accepted password` events and flags any successful login from an IP already flagged for brute force. A single successful login on its own isn't suspicious; a success right after many failures is a likely breach.

## Skills demonstrated

Python · Log analysis · Threat detection · Event correlation · Linux authentication logs · MITRE ATT&CK mapping

## Possible improvements

- Detect successful logins outside normal hours
- Export alerts to CSV or JSON for use in a SIEM
- Check flagged IPs against a threat intelligence feed

## Note

The included `auth.log` is synthetic sample data created for testing.
