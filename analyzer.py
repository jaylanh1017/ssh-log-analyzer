# SSH Log Analyzer
# Reads a Linux SSH auth log and detects brute-force attacks,
# username spraying, and possible account compromise.
#
# Usage:  python3 analyzer.py              (scans auth.log)
#         python3 analyzer.py mylog.log    (scans a different log file)

import os
import sys

# Use the log file given on the command line, or auth.log if none is given
log_path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"

# Stop with a clear message if the file doesn't exist
if not os.path.exists(log_path):
    print(f"Error: can't find the file '{log_path}'")
    sys.exit(1)

THRESHOLD = 5       # this many failures (or more) from one IP counts as brute force
USER_THRESHOLD = 3  # this many different usernames tried from one IP counts as spraying

failed_counts = {}   # { "ip address": number of failed logins }
users_tried = {}     # { "ip address": set of usernames that IP tried }

# Open the log file and go through it one line at a time
with open(log_path, "r") as log_file:
    for line in log_file:

        # We only care about failed login attempts here
        if "Failed password" in line:

            # Split the line into words, then grab the word after "from" (the IP)
            words = line.split()
            ip = words[words.index("from") + 1]

            # The username is the word after "for", or after "invalid user"
            if "invalid user" in line:
                user = words[words.index("user") + 1]
            else:
                user = words[words.index("for") + 1]

            # Add 1 to this IP's failure count (start at 0 if new)
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

            # Remember which usernames this IP tried (a set ignores duplicates)
            if ip not in users_tried:
                users_tried[ip] = set()
            users_tried[ip].add(user)

# Print the results, highest count first
print(f"Scanning: {log_path}")
print()
print("=== Failed Login Attempts by IP ===")
for ip, count in sorted(failed_counts.items(), key=lambda item: item[1], reverse=True):
    print(f"{ip:<18} {count} failed attempts")

print()
print("=== ALERTS ===")

# ---- Detection 1: Brute-force alert ----
for ip, count in failed_counts.items():
    if count >= THRESHOLD:
        print(f"[BRUTE FORCE] {ip} had {count} failed login attempts")

# ---- Detection 2: Username spraying ----
for ip, users in users_tried.items():
    if len(users) >= USER_THRESHOLD:
        user_list = ", ".join(sorted(users))
        print(f"[USERNAME SPRAYING] {ip} tried {len(users)} different usernames: {user_list}")

# ---- Detection 3: Possible compromise (successful login from a brute-force IP) ----
with open(log_path, "r") as log_file:
    for line in log_file:
        if "Accepted password" in line:
            words = line.split()
            ip = words[words.index("from") + 1]
            user = words[words.index("for") + 1]
            time = " ".join(words[0:3])

            if failed_counts.get(ip, 0) >= THRESHOLD:
                print(f"[POSSIBLE COMPROMISE] {ip} logged in as '{user}' at {time} after {failed_counts[ip]} failed attempts")
