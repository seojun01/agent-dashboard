#!/usr/bin/env python3
"""Agent dashboard: Proxmox VMs + agent heartbeats + machine stats pushed by other hosts. stdlib only.

env (all optional, see README):
  PVE_HOST, PVE_TOKEN       Proxmox host and API token ("user@realm!tokenid=secret"); without them the Proxmox pages stay empty
  PVE_TLS_VERIFY=0          accept a self-signed Proxmox certificate (default: verify). PVE_CA_FILE trusts your own CA instead
  AGENT_KEY                 shared secret agents and machine reporters send as X-Key (POST /api/agent, /api/vms)
  BACKUP_KEY                a different secret only the backup-upload job knows (POST /api/backup), so a compromised
                            agent cannot fake a successful backup
  ALLOW_ANON_POST=1         accept POSTs without a key (only for a closed test network); a POST is refused when its key is unset
  BIND (127.0.0.1), PORT (8080)
  PVE_URL, OPNSENSE_URL     sidebar links to the web UIs; a link only shows if its address is known
"""
import gzip, hmac, json, os, re, ssl, time, urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote

PVE_HOST, PVE_TOKEN = os.environ.get("PVE_HOST"), os.environ.get("PVE_TOKEN")
AGENT_KEY = os.environ.get("AGENT_KEY") or None
BACKUP_KEY = os.environ.get("BACKUP_KEY") or None
ALLOW_ANON_POST = os.environ.get("ALLOW_ANON_POST") == "1"
BIND = os.environ.get("BIND", "127.0.0.1")  # loopback by default; set BIND=0.0.0.0 to serve other machines
STALE = 300  # seconds without heartbeat -> shown as "offline"
TFS = ("hour", "day", "week", "month")
CFS = ("AVERAGE", "MAX")
# sidebar links to the web UIs; only the ones whose address is configured are shown
LINKS = [{"name": n, "url": u} for n, u in (
    ("Proxmox", os.environ.get("PVE_URL") or (f"https://{PVE_HOST}:8006" if PVE_HOST else "")),
    ("OPNsense", os.environ.get("OPNSENSE_URL", ""))) if u]
# Proxmox task type -> the wording its own web UI uses; unknown types are shown as-is
TASK_NAMES = {"vzdump": "Backup", "vncproxy": "Console", "vncshell": "Shell", "spiceproxy": "Console",
              "qmstart": "Start", "qmstop": "Stop", "qmshutdown": "Shutdown", "qmreboot": "Reboot", "qmreset": "Reset",
              "vzstart": "Start", "vzstop": "Stop", "vzshutdown": "Shutdown", "vzreboot": "Reboot",
              "qmsnapshot": "Snapshot", "vzsnapshot": "Snapshot", "qmrollback": "Rollback", "vzrollback": "Rollback",
              "qmcreate": "Create VM", "vzcreate": "Create CT", "qmdestroy": "Destroy VM", "vzdestroy": "Destroy CT",
              "qmigrate": "Migrate", "vzmigrate": "Migrate", "qmclone": "Clone", "aptupdate": "Update package database",
              "srvstart": "Start service", "srvstop": "Stop service", "srvreload": "Reload service", "srvrestart": "Restart service"}
# shortcut: all of this state is in memory and lost on restart; persist to a file if that matters
hostvms = {}   # host name -> {host, seen, items, stats}
upload = {}    # last report of the offsite-upload job, pushed by report_upload_job.py on the backup host
hosthist = {}  # host name -> deque of {t, cpu, mem, disk} samples (about 4 hours at one report a minute)
agents = {}    # name -> agent record
events = deque(maxlen=100)  # agent status changes, newest last

# Proxmox usually ships a self-signed certificate. Verification is on by default; PVE_TLS_VERIFY=0 turns it off
# (only do that on a trusted LAN), PVE_CA_FILE makes the proper fix: trust the cluster's own CA.
_ctx = ssl.create_default_context(cafile=os.environ.get("PVE_CA_FILE"))
if os.environ.get("PVE_TLS_VERIFY") == "0":
    _ctx.check_hostname, _ctx.verify_mode = False, ssl.CERT_NONE


def pve_get(path):
    req = urllib.request.Request(f"https://{PVE_HOST}:8006/api2/json{path}",
                                 headers={"Authorization": f"PVEAPIToken={PVE_TOKEN}"})
    return json.load(urllib.request.urlopen(req, timeout=5, context=_ctx))["data"]


_cache = {}  # key -> (fetched_at, value); keeps page refreshes from hammering Proxmox


def cached(key, fn, ttl=30):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    val = fn()
    if val and not (isinstance(val, dict) and "error" in val):  # never cache failures
        _cache[key] = (time.time(), val)
    return val


def configured():
    return bool(PVE_HOST and PVE_TOKEN)


def node():
    return cached("node", lambda: pve_get("/nodes")[0]["node"], 300)


def _series(path, tf, cf, build):
    """rrddata rows -> list of points; build() returns a point dict or None to skip a row."""
    rows = pve_get(f"{path}/rrddata?timeframe={tf}&cf={cf}")
    return [p for p in map(build, rows) if p]


def _norm(tf, cf):
    return (tf if tf in TFS else "hour"), (cf if cf in CFS else "AVERAGE")  # both go into the API path


def graphs(tf, cf):
    """Host usage history from Proxmox's own RRD store: fractions 0-1, bytes, net bytes/s."""
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set", "points": []}
    tf, cf = _norm(tf, cf)

    def build(r):
        if r.get("cpu") is None or not r.get("memtotal"):
            return None
        return {"t": r["time"], "cpu": r["cpu"], "iowait": r.get("iowait") or 0,
                "mem": r["memused"] / r["memtotal"], "memb": r["memused"], "memtotal": r["memtotal"],
                "load": r.get("loadavg") or 0,
                "swap": (r.get("swapused") or 0) / r["swaptotal"] if r.get("swaptotal") else 0,
                "disk": r["rootused"] / r["roottotal"] if r.get("roottotal") else 0,
                "netin": r.get("netin") or 0, "netout": r.get("netout") or 0}

    def go():
        try:
            return {"points": _series(f"/nodes/{node()}", tf, cf, build)}
        except Exception as e:
            return {"error": str(e), "points": []}
    return cached(("g", tf, cf), go)


def _vm_ok(kind, vmid):
    return kind in ("qemu", "lxc") and re.fullmatch(r"\d{1,9}", vmid or "")  # these go into the API path


def vmgraph(kind, vmid, tf, cf):
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set", "points": []}
    if not _vm_ok(kind, vmid):
        return {"error": "bad vm", "points": []}
    tf, cf = _norm(tf, cf)

    def build(r):
        if r.get("cpu") is None or not r.get("maxmem"):
            return None
        return {"t": r["time"], "cpu": r["cpu"], "mem": (r.get("mem") or 0) / r["maxmem"],
                "memb": r.get("mem") or 0, "memtotal": r["maxmem"],
                "netin": r.get("netin") or 0, "netout": r.get("netout") or 0,
                "diskr": r.get("diskread") or 0, "diskw": r.get("diskwrite") or 0}

    def go():
        try:
            return {"points": _series(f"/nodes/{node()}/{kind}/{vmid}", tf, cf, build)}
        except Exception as e:
            return {"error": str(e), "points": []}
    return cached(("v", kind, vmid, tf, cf), go)


def vminfo(kind, vmid):
    """Current status of one VM/CT (swap and disk usage are only in here, not in cluster/resources)."""
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set"}
    if not _vm_ok(kind, vmid):
        return {"error": "bad vm"}

    def go():
        try:
            s = pve_get(f"/nodes/{node()}/{kind}/{vmid}/status/current")
        except Exception as e:
            return {"error": str(e)}
        return {k: s.get(k) for k in ("status", "uptime", "cpu", "cpus", "mem", "maxmem",
                                      "swap", "maxswap", "disk", "maxdisk", "name")}
    return cached(("i", kind, vmid), go, 10)


def tasks(vmid):
    """Recent Proxmox tasks (what the web UI shows in its Tasks panel), optionally for one VM/CT."""
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set", "items": []}
    if vmid and not re.fullmatch(r"\d{1,9}", vmid):
        return {"error": "bad vmid", "items": []}

    def go():
        try:
            rows = pve_get(f"/nodes/{node()}/tasks?limit=30" + (f"&vmid={vmid}" if vmid else ""))
        except Exception as e:
            return {"error": str(e), "items": []}
        out = []
        for r in rows:
            label = TASK_NAMES.get(r.get("type", ""), r.get("type", ""))
            tid = str(r.get("id") or "")
            out.append({"start": r.get("starttime"), "end": r.get("endtime"), "node": r.get("node"),
                        "user": r.get("user"), "desc": f"VM/CT {tid} - {label}" if tid.isdigit() else label,
                        "status": r.get("status") or "running"})
        return {"items": out}
    return cached(("t", vmid), go, 10)


def kv(s):
    """'virtio=AA:BB,bridge=vmbr0,firewall=1' -> dict; a leading bare token (the volume) goes under '_'."""
    out = {}
    for i, p in enumerate(str(s).split(",")):
        if "=" in p:
            k, v = p.split("=", 1)
            out[k] = v
        elif i == 0:
            out["_"] = p
    return out


_DISK_RE = re.compile(r"^((scsi|sata|virtio|ide|mp)\d+|rootfs|efidisk0|tpmstate0)$")
_FACTS = ("cores", "sockets", "vcpus", "cpu", "memory", "swap", "balloon", "bios", "machine", "ostype", "arch",
          "boot", "onboot", "agent", "unprivileged", "hostname", "startup", "protection")


def vmdetail(kind, vmid):
    """Hardware config, snapshots and guest IPs of one VM/CT (the pieces of the Proxmox summary the charts lack)."""
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set"}
    if not _vm_ok(kind, vmid):
        return {"error": "bad vm"}

    def go():
        base = f"/nodes/{node()}/{kind}/{vmid}"
        try:
            c = pve_get(base + "/config")
        except Exception as e:
            return {"error": str(e)}
        out = {"facts": [[k, str(c[k])] for k in _FACTS if k in c], "desc": str(c.get("description", ""))[:500],
               "nics": [], "disks": [], "snapshots": [], "ips": []}
        for k, v in sorted(c.items()):
            d = kv(v) if isinstance(v, str) else {}
            if re.fullmatch(r"net\d+", k):
                model = next((m for m in ("virtio", "e1000", "rtl8139", "vmxnet3", "veth") if m in d or d.get("type") == m), "")
                out["nics"].append({"id": k, "model": model, "mac": d.get(model) or d.get("hwaddr", ""),
                                    "bridge": d.get("bridge", ""), "ip": d.get("ip", ""), "firewall": d.get("firewall") == "1"})
            elif _DISK_RE.match(k):
                out["disks"].append({"id": k, "volume": d.get("_", ""), "size": d.get("size", ""), "media": d.get("media", "")})
        try:
            out["snapshots"] = [{"name": s["name"], "desc": s.get("description", ""), "time": s.get("snaptime"),
                                 "parent": s.get("parent", "")} for s in pve_get(base + "/snapshot") if s["name"] != "current"]
        except Exception:
            pass  # no audit permission on snapshots: show none
        try:  # guest IPs need LXC interfaces or the qemu guest agent; failing is normal
            if kind == "lxc":
                out["ips"] = [i["inet"] for i in pve_get(base + "/interfaces") if i.get("name") != "lo" and i.get("inet")]
            else:
                out["ips"] = [f"{a['ip-address']}/{a['prefix']}" for i in pve_get(base + "/agent/network-get-interfaces")["result"]
                              if i["name"] != "lo" for a in i.get("ip-addresses", []) if a["ip-address-type"] == "ipv4"]
        except Exception:
            pass
        return out
    return cached(("d", kind, vmid), go, 30)


def nodedetail():
    """Network interfaces and physical disks of the node."""
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set"}

    def go():
        try:
            n = node()
        except Exception as e:
            return {"error": str(e)}
        out = {"network": [], "disks": []}
        try:
            out["network"] = [{k: i.get(k) for k in ("iface", "type", "address", "cidr", "gateway", "bridge_ports", "active")}
                              for i in pve_get(f"/nodes/{n}/network")]
        except Exception as e:
            out["network_error"] = str(e)
        try:
            out["disks"] = [{k: d.get(k) for k in ("devpath", "model", "size", "type", "health", "wearout", "vendor")}
                            for d in pve_get(f"/nodes/{n}/disks/list")]
        except Exception as e:
            out["disks_error"] = str(e)
        return out
    return cached("nodedetail", go, 60)


def _task_log(upid):
    return [l["t"] for l in pve_get(f"/nodes/{node()}/tasks/{quote(upid, safe='')}/log?limit=500")]


def _vzdump_size(upid):
    """Archive size printed in a finished vzdump log; 'n/a' is cached too so a missing line is not refetched."""
    def go():
        try:
            for t in reversed(_task_log(upid)):
                m = re.search(r"archive file size: ([\d.]+ ?[KMGT]i?B)", t)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return "n/a"
    return cached(("sz", upid), go, 6 * 3600)


def _progress(upid):
    """Percent / detail / guest of a running vzdump task, read from its log."""
    try:
        lines = _task_log(upid)
    except Exception:
        return {}
    pct = det = guest = None
    for t in lines:
        m = re.search(r"Starting Backup of VM (\d+)", t)
        guest = int(m.group(1)) if m else guest
        m = re.search(r"(\d+)% \(([^)]*)\)", t)
        pct, det = (int(m.group(1)), m.group(2)) if m else (pct, det)
    return {"percent": pct, "detail": det, "vmid": guest, "line": lines[-1] if lines else ""}


def _prune(j):
    """Retention of a backup job as text; the API sends prune-backups as an object or a string, older jobs use maxfiles."""
    p = j.get("prune-backups")
    if isinstance(p, dict):
        p = ",".join(f"{k}={v}" for k, v in p.items())
    return p or (f"keep-last={j['maxfiles']}" if j.get("maxfiles") else "")


def backups():
    """Backup jobs, running progress, per-guest last result, history and archives (Proxmox side of the backup pipeline)."""
    now = time.time()
    up = {**upload, "age": int(now - upload["t"])} if upload else None  # reported by the upload job, independent of Proxmox
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set", "now": now, "upload": up}

    def go():
        try:
            n = node()
        except Exception as e:
            return {"error": str(e)}
        res = {"jobs": [], "history": [], "running": [], "files": [], "guests": []}
        try:
            for j in pve_get("/cluster/backup"):
                res["jobs"].append({
                    "id": j.get("id"), "enabled": j.get("enabled", 1), "schedule": j.get("schedule"),
                    "vmid": str(j.get("vmid", "")), "all": bool(j.get("all")), "storage": j.get("storage"),
                    "mode": j.get("mode"), "compress": j.get("compress"), "next_run": j.get("next-run"),
                    "prune": _prune(j)})
        except Exception as e:
            res["jobs_error"] = str(e)
        try:
            rows = sorted(pve_get(f"/nodes/{n}/tasks?typefilter=vzdump&limit=60"), key=lambda r: -r.get("starttime", 0))
        except Exception as e:
            rows = []
            res["tasks_error"] = str(e)
        for r in rows:
            tid = str(r.get("id") or "")
            if r.get("endtime") is None:  # no end time = still running
                p = _progress(r["upid"])
                res["running"].append({"vmid": tid or (str(p["vmid"]) if p.get("vmid") else ""), "start": r.get("starttime"),
                                       "percent": p.get("percent"), "detail": p.get("detail"), "line": p.get("line", "")})
            else:
                res["history"].append({"vmid": tid, "start": r.get("starttime"), "end": r.get("endtime"),
                                       "status": r.get("status") or "OK", "upid": r["upid"]})
        stores = {j["storage"] for j in res["jobs"] if j.get("storage")}
        try:
            stores |= {s["storage"] for s in pve_get("/cluster/resources?type=storage") if "backup" in (s.get("content") or "")}
        except Exception:
            pass
        for st in sorted(stores):
            try:
                for f in pve_get(f"/nodes/{n}/storage/{quote(st, safe='')}/content?content=backup"):
                    res["files"].append({"volid": f.get("volid"), "storage": st, "vmid": str(f.get("vmid", "")),
                                         "size": f.get("size"), "ctime": f.get("ctime"), "format": f.get("format")})
            except Exception as e:
                res.setdefault("files_error", str(e))
        res["files"].sort(key=lambda f: -(f.get("ctime") or 0))
        # a token without VM.Backup gets an empty backup list even though archives exist; say so instead of showing "0"
        res["files_hidden"] = not res["files"] and any(h["status"] == "OK" for h in res["history"])
        try:
            names = {str(r["vmid"]): r for r in pve_get("/cluster/resources?type=vm")}
        except Exception:
            names = {}
        vmids = {str(j) for jb in res["jobs"] for j in jb["vmid"].split(",") if j} | {h["vmid"] for h in res["history"] if h["vmid"]} \
            | {f["vmid"] for f in res["files"] if f["vmid"]} | {r["vmid"] for r in res["running"] if r["vmid"]}
        for vmid in sorted(vmids, key=int):
            jobs = [j for j in res["jobs"] if j["all"] or vmid in j["vmid"].split(",")]
            last = next((h for h in res["history"] if h["vmid"] == vmid), None)
            fl = [f for f in res["files"] if f["vmid"] == vmid]
            runs = [j["next_run"] for j in jobs if j["enabled"] and j.get("next_run")]
            res["guests"].append({
                "vmid": int(vmid), "name": (names.get(vmid) or {}).get("name", ""), "type": (names.get(vmid) or {}).get("type", ""),
                "schedule": ", ".join(sorted({j["schedule"] for j in jobs if j.get("schedule")})), "enabled": any(j["enabled"] for j in jobs),
                "prune": next((j["prune"] for j in jobs if j["prune"]), ""), "next_run": min(runs) if runs else None,
                "last": last and {"start": last["start"], "end": last["end"], "status": last["status"]},
                "last_size": _vzdump_size(last["upid"]) if last and last["status"] == "OK" else None,
                "copies": len(fl), "total": sum(f.get("size") or 0 for f in fl)})
        res["history"] = res["history"][:30]
        res["files"] = res["files"][:60]
        return res
    return {**cached("backups", go, 5), "now": now, "upload": up}


def hostinfo():
    if not configured():
        return None

    def go():
        try:
            n = node()
            s = pve_get(f"/nodes/{n}/status")
        except Exception:
            return None
        ci = s.get("cpuinfo") or {}
        return {"node": n, "pve": s.get("pveversion"), "kernel": s.get("kversion"),
                "cpu_model": ci.get("model"), "cores": ci.get("cpus"), "sockets": ci.get("sockets"),
                "uptime": s.get("uptime"), "load": s.get("loadavg"), "rootfs": s.get("rootfs"),
                "swap": s.get("swap"), "mem": s.get("memory")}
    return cached("hostinfo", go)


def vms():
    if not configured():
        return {"error": "PVE_HOST / PVE_TOKEN not set", "items": []}
    try:
        data = pve_get("/cluster/resources")
    except Exception as e:
        return {"error": str(e), "items": []}
    keep = [d for d in data if d["type"] in ("qemu", "lxc", "node")]
    return {"items": [{k: d.get(k) for k in
            ("type", "vmid", "name", "node", "status", "cpu", "mem", "maxmem", "uptime",
             "maxcpu", "disk", "maxdisk", "netin", "netout")} for d in keep],
            "storage": [{"name": d.get("storage"), "node": d.get("node"), "status": d.get("status"),
                         "used": d.get("disk"), "total": d.get("maxdisk"), "type": d.get("plugintype"),
                         "content": d.get("content"), "shared": d.get("shared")}
                        for d in data if d["type"] == "storage"]}


def timeline(name, now, window=6 * 3600):
    """[[start_age, end_age, status], ...] seconds ago, from the status-change events of the last 6 hours."""
    ev = sorted((e for e in events if e["name"] == name), key=lambda e: e["t"])
    segs = []
    for i, e in enumerate(ev):
        start, end = max(e["t"], now - window), (ev[i + 1]["t"] if i + 1 < len(ev) else now)
        if end > start:
            segs.append([int(now - start), int(now - end), e["status"]])
    return segs


def status():
    now = time.time()
    for a in agents.values():  # log the moment an agent went quiet
        if now - a["seen"] >= STALE and not a["dark"]:
            a["dark"] = True
            events.append({"t": a["seen"] + STALE, "name": a["name"], "host": a["host"],
                           "status": "offline", "task": a["task"]})
    ag = [{"name": a["name"], "host": a["host"], "task": a["task"], "beats": a["beats"],
           "status": "offline" if a["dark"] else a["status"],
           "age": int(now - a["seen"]), "since_age": int(now - a["since"]),
           "timeline": timeline(a["name"], now)} for a in agents.values()]
    ev = [{**e, "age": int(now - e["t"])} for e in sorted(events, key=lambda e: -e["t"])[:40]]
    hv = [{**h, "age": int(now - h["seen"]), "hist": list(hosthist.get(h["host"], []))} for h in hostvms.values()]
    return {"vms": vms(), "host": hostinfo(), "links": LINKS, "hostvms": hv,
            "agents": sorted(ag, key=lambda a: a["name"]), "events": ev}


class H(BaseHTTPRequestHandler):
    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")  # the dashboard has no reason to be embedded elsewhere
        self.send_header("Cache-Control", "no-store")

    def _send(self, code, ctype, body):
        """Send a response, gzip-compressed when the client accepts it (the status JSON is ~13 KB, ~2 KB compressed)."""
        gz = len(body) > 512 and "gzip" in self.headers.get("Accept-Encoding", "")
        if gz:
            body = gzip.compress(body, 5)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Vary", "Accept-Encoding")
        if gz:
            self.send_header("Content-Encoding", "gzip")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj).encode())

    def _authorized(self):
        """Each POST needs its own key (backup reports: BACKUP_KEY, everything else: AGENT_KEY).
        A key that is not configured refuses the endpoint unless ALLOW_ANON_POST=1."""
        key = BACKUP_KEY if self.path == "/api/backup" else AGENT_KEY
        if not key:
            return ALLOW_ANON_POST
        return hmac.compare_digest(self.headers.get("X-Key", "").encode(), key.encode())  # constant-time

    def do_GET(self):
        self.path, _, qs = self.path.partition("?")
        q = {k: v[0] for k, v in parse_qs(qs).items()}
        tf, cf = q.get("tf", "hour"), q.get("cf", "AVERAGE")
        if self.path == "/api/status":
            return self._json(status())
        if self.path == "/api/graphs":
            return self._json(graphs(tf, cf))
        if self.path == "/api/vmgraph":
            return self._json(vmgraph(q.get("type", ""), q.get("vmid", ""), tf, cf))
        if self.path == "/api/vminfo":
            return self._json(vminfo(q.get("type", ""), q.get("vmid", "")))
        if self.path == "/api/backups":
            return self._json(backups())
        if self.path == "/api/vmdetail":
            return self._json(vmdetail(q.get("type", ""), q.get("vmid", "")))
        if self.path == "/api/nodedetail":
            return self._json(nodedetail())
        if self.path == "/api/tasks":
            return self._json(tasks(q.get("vmid", "")))
        if self.path in ("/", "/index.html"):
            with open(os.path.join(os.path.dirname(__file__), "index.html"), "rb") as f:
                return self._send(200, "text/html; charset=utf-8", f.read())
        self.send_error(404)

    def do_POST(self):
        if self.path not in ("/api/agent", "/api/vms", "/api/backup"):
            return self.send_error(404)
        if not self._authorized():
            return self._json({"error": "forbidden: send the matching key as X-Key (AGENT_KEY, or BACKUP_KEY for /api/backup)"}, 403)
        now = time.time()
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 16384)))
            if self.path == "/api/vms":  # machine stats of another host (e.g. the Mac), pushed by report_mac.py
                host = str(d["host"])[:32]
                st = d.get("stats") or {}
                hostvms[host] = {"host": host, "seen": now, "items": [
                    {"name": str(i["name"])[:64], "status": str(i["status"])[:16]} for i in d["items"][:30]],
                    "stats": {k: float(st[k]) for k in
                              ("cpu", "mem_used", "mem_total", "disk_used", "disk_total", "uptime") if k in st}}
                s = hostvms[host]["stats"]
                if s.get("mem_total") and s.get("disk_total"):
                    hosthist.setdefault(host, deque(maxlen=240)).append(
                        {"t": now, "cpu": s.get("cpu", 0), "mem": s["mem_used"] / s["mem_total"],
                         "disk": s["disk_used"] / s["disk_total"]})
                return self._json({"ok": True})
            if self.path == "/api/backup":  # result of the Drive upload job, pushed when it finishes
                upload.clear()
                upload.update({"t": now, "status": str(d.get("status", "ok"))[:16], "started": int(d.get("started") or 0) or None,
                               "finished": int(d.get("finished") or now), "files": int(d.get("files") or 0),
                               "bytes": int(d.get("bytes") or 0), "error": str(d.get("error", ""))[:300],
                               "log": [str(l)[:300] for l in (d.get("log") or [])[:20]]})
                return self._json({"ok": True})
            name = str(d["name"])[:64]
        except Exception:
            return self._json({"error": "need JSON {name, host?, status?, task?}, {host, items:[{name,status}], stats?} or {status, ...}"}, 400)
        host, st, task = str(d.get("host", ""))[:32], str(d.get("status", "working"))[:16], str(d.get("task", ""))[:200]
        a = agents.get(name)
        if not a or a["status"] != st or a["task"] != task or a["dark"]:
            events.append({"t": now, "name": name, "host": host, "status": st, "task": task})
        changed = not a or a["status"] != st or a["dark"]
        agents[name] = {"name": name, "host": host, "status": st, "task": task, "seen": now, "dark": False,
                        "since": now if changed else a["since"], "beats": (a["beats"] if a else 0) + 1}
        self._json({"ok": True})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    for name, key in (("AGENT_KEY", AGENT_KEY), ("BACKUP_KEY", BACKUP_KEY)):
        if not key and not ALLOW_ANON_POST:
            print(f"note: {name} is not set, so the matching reports are refused (see README).")
    print(f"dashboard on {BIND}:{port}")
    ThreadingHTTPServer((BIND, port), H).serve_forever()
