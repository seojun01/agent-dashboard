#!/usr/bin/env python3
"""Show the Antigravity agent (CLI "agy" or the IDE) on the dashboard as working, idle or offline.

Run it every 30 seconds from launchd or cron on the Mac that runs Antigravity.
usage: DASH_URL=http://dashboard.example:8080 AGENT_KEY=<shared key> python3 report_antigravity.py [host-label]

Antigravity writes its transcript and conversation database while the agent works, so "working" means one of those
files changed in the last 45 seconds. Only the status and the name of the working folder are sent, never prompts or
file contents. Nothing is reported when Antigravity is not installed.
"""
import glob, json, os, subprocess, sys, time, urllib.request

host = sys.argv[1] if len(sys.argv) > 1 else "My Mac"
ACTIVE_WITHIN = 45  # seconds
ACTIVITY = ["~/.gemini/antigravity*/brain/*/.system_generated/logs/transcript.jsonl", "~/.gemini/antigravity*/conversations/*.db-wal"]


def out(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout


def last_activity():
    newest = 0
    for pattern in ACTIVITY:
        for f in glob.glob(os.path.expanduser(pattern)):
            try:
                newest = max(newest, os.path.getmtime(f))
            except OSError:
                pass  # the file was rotated away between glob and stat
    return newest


def folder(pid):
    for line in out("lsof", "-a", "-p", pid, "-d", "cwd", "-Fn").splitlines():
        if line.startswith("n") and line != "n/":
            return os.path.basename(line[1:])
    return ""


if not glob.glob(os.path.expanduser("~/.gemini/antigravity*")) and not glob.glob("/Applications/Antigravity.app"):
    sys.exit(0)
cli = out("pgrep", "-x", "agy").split()
running = cli or out("pgrep", "-f", "Antigravity.app/Contents/MacOS/").split()
if not running:
    status, task = "offline", "Antigravity is not running"
elif time.time() - last_activity() < ACTIVE_WITHIN:
    where = next((f for f in map(folder, cli) if f), "")
    status, task = "working", f"Working in {where}" if where else "Working"
else:
    status, task = "idle", "Waiting for input"

req = urllib.request.Request(
    os.environ.get("DASH_URL", "http://127.0.0.1:8080") + "/api/agent",
    json.dumps({"name": "antigravity", "host": host, "status": status, "task": task}).encode(),
    {"X-Key": os.environ.get("AGENT_KEY", "")})
print(status, urllib.request.urlopen(req, timeout=10).read().decode())
