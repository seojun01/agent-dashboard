#!/usr/bin/env python3
"""Report this Mac's UTM VMs and machine stats to the dashboard. Run it on the Mac, e.g. every minute via launchd/cron.

usage: DASH_URL=http://dashboard.example:8080 AGENT_KEY=<shared key> python3 report_utm.py [host-label]
"""
import json, os, re, shutil, subprocess, sys, time, urllib.request

UTMCTL = "/Applications/UTM.app/Contents/MacOS/utmctl"
host = sys.argv[1] if len(sys.argv) > 1 else "My Mac"


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=True).stdout


def stats():
    vm = run("vm_stat")
    page = int(re.search(r"page size of (\d+)", vm).group(1))
    pages = lambda k: int(re.search(rf"{k}:\s+(\d+)", vm).group(1))
    used = (pages("Pages active") + pages("Pages wired down") + pages("Pages occupied by compressor")) * page
    du = shutil.disk_usage("/")
    boot = int(re.search(r"sec = (\d+)", run("sysctl", "-n", "kern.boottime")).group(1))
    return {"cpu": min(1, os.getloadavg()[0] / os.cpu_count()),  # 1-min load per core, not instantaneous CPU %
            "mem_used": used, "mem_total": int(run("sysctl", "-n", "hw.memsize")),
            "disk_used": du.used, "disk_total": du.total, "uptime": time.time() - boot}


# lines: "<uuid> <status> <name with spaces>", first line is the header
items = [{"name": p[2], "status": p[1]} for p in (l.split(None, 2) for l in run(UTMCTL, "list").splitlines()[1:]) if len(p) == 3]
try:
    st = stats()
except Exception as e:  # still report the VM list if a stat command fails
    print("stats skipped:", e, file=sys.stderr)
    st = {}
req = urllib.request.Request(
    os.environ.get("DASH_URL", "http://127.0.0.1:8080") + "/api/vms",
    json.dumps({"host": host, "items": items, "stats": st}).encode(),
    {"X-Key": os.environ.get("AGENT_KEY", "")})
print(urllib.request.urlopen(req, timeout=10).read().decode())
