#!/usr/bin/env python3
"""Tell the dashboard how your offsite-upload job went (rclone, rsync, anything run by a systemd service).

Run it as the last step of that service. Add one line to the [Service] section of the unit:

    ExecStopPost=/usr/local/sbin/report_upload_job.py
    Environment=UPLOAD_UNIT=my-upload.service DASH_URL=http://dashboard.example:8080
    EnvironmentFile=/etc/report_upload_job.env      # contains: AGENT_KEY=<shared key>, mode 600

systemd gives ExecStopPost the result of the main command in $SERVICE_RESULT ("success" when it worked).
If the job stops running altogether, the dashboard turns the card red after 26 hours without a report.
"""
import json, os, subprocess, sys, time, urllib.request

UNIT = os.environ.get("UPLOAD_UNIT")
if not UNIT:
    sys.exit("set UPLOAD_UNIT to the name of the systemd service that runs the upload")


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout


def epoch(prop):  # e.g. ExecMainStartTimestamp=Mon 2026-11-23 05:00:01 UTC -> unix seconds, 0 if unknown
    v = sh("systemctl", "show", UNIT, "-p", prop, "--value").strip()
    try:
        return int(subprocess.run(["date", "-d", v, "+%s"], capture_output=True, text=True).stdout)
    except ValueError:
        return 0


ok = os.environ.get("SERVICE_RESULT", "success") == "success"
log = [l for l in sh("journalctl", "-u", UNIT, "-n", "15", "--no-pager", "-o", "cat").splitlines() if l.strip()]
body = {"status": "ok" if ok else "failed", "started": epoch("ExecMainStartTimestamp"), "finished": int(time.time()),
        "error": "" if ok else f"{os.environ.get('SERVICE_RESULT')} (exit {os.environ.get('EXIT_STATUS', '?')})", "log": log}
req = urllib.request.Request(os.environ.get("DASH_URL", "http://127.0.0.1:8080") + "/api/backup",
                             json.dumps(body).encode(), {"X-Key": os.environ.get("AGENT_KEY", "")})
print(urllib.request.urlopen(req, timeout=10).read().decode())
