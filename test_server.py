"""Self-check for the access rules of server.py. Run: python3 -m unittest test_server -v"""
import importlib, json, os, threading, unittest, urllib.error, urllib.request
from http.server import ThreadingHTTPServer


def start(**env):
    """Import a fresh copy of server.py with the given environment and serve it on a free loopback port."""
    for k in ("AGENT_KEY", "BACKUP_KEY", "STATE_FILE", "ALLOW_ANON_POST", "PVE_HOST", "PVE_TOKEN", "BIND", "PVE_TLS_VERIFY"):
        os.environ.pop(k, None)
    os.environ.update(env)
    import server
    srv = importlib.reload(server)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return srv, httpd, f"http://127.0.0.1:{httpd.server_port}"


def stop(httpd):
    httpd.shutdown()
    httpd.server_close()


def call(url, body=None, key=None):
    req = urllib.request.Request(url, None if body is None else json.dumps(body).encode(), {"X-Key": key} if key else {})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, dict(r.headers), json.loads(r.read() or b"null") if "json" in r.headers.get("Content-Type", "") else None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"null")


class Access(unittest.TestCase):
    def test_post_refused_without_configured_key(self):
        _, h, base = start()
        self.assertEqual(call(base + "/api/agent", {"name": "a"})[0], 403)
        self.assertEqual(call(base + "/api/agent", {"name": "a"}, key="anything")[0], 403)
        stop(h)

    def test_post_needs_the_right_key(self):
        _, h, base = start(AGENT_KEY="s3cret")
        self.assertEqual(call(base + "/api/agent", {"name": "a"})[0], 403)
        self.assertEqual(call(base + "/api/agent", {"name": "a"}, key="wrong")[0], 403)
        self.assertEqual(call(base + "/api/agent", {"name": "a", "status": "idle"}, key="s3cret")[0], 200)
        names = [a["name"] for a in call(base + "/api/status")[2]["agents"]]
        self.assertEqual(names, ["a"])
        stop(h)

    def test_mac_stats_report_without_vms(self):
        _, h, base = start(AGENT_KEY="k")
        stats = {"cpu": .2, "mem_used": 8, "mem_total": 16, "disk_used": 1, "disk_total": 4, "uptime": 60}
        self.assertEqual(call(base + "/api/vms", {"host": "My Mac", "items": [], "stats": stats}, key="k")[0], 200)
        host = call(base + "/api/status")[2]["hostvms"][0]
        self.assertEqual((host["items"], len(host["hist"]), host["hist"][0]["mem"]), ([], 1, .5))
        stop(h)

    def test_agent_key_cannot_fake_a_backup_report(self):
        _, h, base = start(AGENT_KEY="a", BACKUP_KEY="b")
        self.assertEqual(call(base + "/api/backup", {"status": "ok"}, key="a")[0], 403)  # an agent must not be able to do this
        self.assertEqual(call(base + "/api/agent", {"name": "x"}, key="b")[0], 403)      # and the backup key is no agent key
        self.assertEqual(call(base + "/api/backup", {"status": "failed"}, key="b")[0], 200)
        self.assertEqual(call(base + "/api/agent", {"name": "x"}, key="a")[0], 200)
        self.assertEqual(call(base + "/api/backups")[2]["upload"]["status"], "failed")
        stop(h)

    def test_backup_endpoint_needs_its_own_key_to_be_set(self):
        _, h, base = start(AGENT_KEY="a")  # BACKUP_KEY not configured
        self.assertEqual(call(base + "/api/backup", {"status": "ok"}, key="a")[0], 403)
        stop(h)

    def test_responses_are_compressed_only_when_the_client_asks(self):
        import gzip
        _, h, base = start(AGENT_KEY="k")
        for i in range(8):  # make /api/status bigger than the 512-byte threshold below which nothing is compressed
            call(base + "/api/agent", {"name": f"agent-{i}", "task": "x" * 200}, key="k")
        plain = urllib.request.urlopen(base + "/api/status", timeout=5)
        self.assertIsNone(plain.headers.get("Content-Encoding"))
        plain_size = len(plain.read())
        r = urllib.request.urlopen(urllib.request.Request(base + "/api/status", headers={"Accept-Encoding": "gzip"}), timeout=5)
        body = r.read()
        self.assertEqual(r.headers.get("Content-Encoding"), "gzip")
        self.assertLess(len(body), plain_size / 3)
        self.assertEqual(len(json.loads(gzip.decompress(body))["agents"]), 8)
        small = urllib.request.urlopen(urllib.request.Request(base + "/api/graphs", headers={"Accept-Encoding": "gzip"}), timeout=5)
        self.assertIsNone(small.headers.get("Content-Encoding"))  # tiny responses stay plain
        page = urllib.request.urlopen(urllib.request.Request(base + "/", headers={"Accept-Encoding": "gzip"}), timeout=5)
        self.assertEqual(page.headers.get("Content-Encoding"), "gzip")
        self.assertIn(b"<title>", gzip.decompress(page.read()))
        stop(h)

    def test_upload_report_survives_a_restart(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "state.json")
        _, h, base = start(BACKUP_KEY="b", STATE_FILE=path)
        self.assertEqual(call(base + "/api/backup", {"status": "ok", "files": 3}, key="b")[0], 200)
        stop(h)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")  # the state file is private
        _, h, base = start(BACKUP_KEY="b", STATE_FILE=path)            # a fresh import is a restart: it loads the file
        up = call(base + "/api/backups")[2]["upload"]
        self.assertEqual((up["status"], up["files"]), ("ok", 3))
        stop(h)
        with open(path, "w") as f:
            f.write("{broken")                                          # a damaged file must not stop the server
        _, h, base = start(BACKUP_KEY="b", STATE_FILE=path)
        self.assertIsNone(call(base + "/api/backups")[2]["upload"])
        stop(h)

    def test_anonymous_post_only_when_explicitly_allowed(self):
        _, h, base = start(ALLOW_ANON_POST="1")
        self.assertEqual(call(base + "/api/agent", {"name": "a"})[0], 200)
        stop(h)

    def test_defaults_are_safe(self):
        srv, h, base = start()
        self.assertEqual(srv.BIND, "127.0.0.1")          # loopback unless BIND is set
        self.assertEqual(srv.LINKS, [])                  # no built-in internal addresses
        self.assertTrue(srv._ctx.check_hostname)         # TLS verification on unless PVE_TLS_VERIFY=0
        _, headers, _ = call(base + "/api/status")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        stop(h)

    def test_tls_opt_out_and_links(self):
        srv, h, _ = start(PVE_HOST="pve.example.lan", PVE_TOKEN="u@pve!t=x", PVE_TLS_VERIFY="0")
        self.assertFalse(srv._ctx.check_hostname)
        self.assertEqual(srv.LINKS, [{"name": "Proxmox", "url": "https://pve.example.lan:8006"}])
        stop(h)

    def test_vm_ids_are_validated_before_reaching_proxmox(self):
        _, h, base = start(PVE_HOST="127.0.0.1", PVE_TOKEN="u@pve!t=x")
        for q in ("type=../x&vmid=1", "type=lxc&vmid=1/../2", "type=qemu&vmid=x"):
            self.assertIn("bad vm", json.dumps(call(f"{base}/api/vmgraph?{q}")[2]))
            self.assertIn("bad vm", json.dumps(call(f"{base}/api/vmdetail?{q}")[2]))
        self.assertIn("bad vmid", json.dumps(call(base + "/api/tasks?vmid=1;ls")[2]))
        stop(h)


if __name__ == "__main__":
    unittest.main()
