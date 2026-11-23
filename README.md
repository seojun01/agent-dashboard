# agent-dashboard

A small dashboard for a home lab: the state of your **Proxmox** VMs and containers, the status of the **agents** working for you (scripts, bots, coding assistants), the **backup** pipeline, and the load, memory and disk of other machines such as a laptop. One Python file with no dependencies, one HTML page.

- **Overview**: host CPU/memory/disk, usage charts, VMs, agents, storage, latest backups and tasks
- **Node and VM/CT pages** in the layout of the Proxmox web UI: status panel, area charts (hour/day/week/month, average/maximum), hardware, snapshots, tasks
- **Backups**: running progress, last result per guest, history, archives, and whether your offsite upload keeps running
- **Agents**: only agents that are working, or worked in the last 30 minutes (most recent first, at most 5); idle and offline ones stay behind a "Show more" line. Status, current task, a 6-hour status strip, recent activity
- Light and dark theme, no external requests, no build step

## Quick start

```sh
python3 server.py            # http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080/?demo` to look around with made-up data, no Proxmox needed.

To show real data, create a **read-only Proxmox API token** and pass it in the environment (see `.env.example`):

```sh
# on the Proxmox host
pveum user add dashboard@pve
pveum user token add dashboard@pve dash --privsep 1
pveum acl modify / --roles PVEAuditor --users dashboard@pve --tokens 'dashboard@pve!dash'
```

```sh
export PVE_HOST=pve.example.lan PVE_TOKEN='dashboard@pve!dash=<secret>' AGENT_KEY=$(openssl rand -hex 16) BACKUP_KEY=$(openssl rand -hex 16)
export PVE_TLS_VERIFY=0      # only if Proxmox uses its self-signed certificate; see Security
python3 server.py
```

Notes on the token: a privilege-separated token only gets what both the user and the token are allowed, so the role is set on both. Proxmox hides backup archives from `PVEAuditor`. Without them the Backups page still shows results and sizes from the task history. To list archives, additionally allow `VM.Backup` (a write permission; decide for yourself).

## Configuration

| Variable | Meaning |
|---|---|
| `PVE_HOST`, `PVE_TOKEN` | Proxmox address and token. Without them the Proxmox pages stay empty |
| `PVE_CA_FILE` | Trust your own CA for the Proxmox certificate (preferred) |
| `PVE_TLS_VERIFY=0` | Accept a self-signed Proxmox certificate. Default: verify |
| `AGENT_KEY` | Secret that agents and machine reporters send (`/api/agent`, `/api/vms`). **Required** for those POSTs |
| `BACKUP_KEY` | A *different* secret, known only to the backup-upload job (`/api/backup`). **Required** for that POST. Keeping it apart means a hijacked agent cannot report a fake "upload ok" |
| `ALLOW_ANON_POST=1` | Accept POSTs without a key. Only for a closed test network |
| `STATE_FILE` | Optional path (mode 600). Keeps the last backup-upload report across restarts; everything else lives in memory and is rebuilt as agents report again |
| `BIND` / `PORT` | Listen address (default `127.0.0.1`) and port (default `8080`) |
| `PVE_URL`, `OPNSENSE_URL` | Sidebar links to the web UIs. A link shows only when its address is known |

## Reporting agents and machines

Agents tell the dashboard what they do by posting a heartbeat. No heartbeat for 5 minutes shows the agent as offline.

```sh
curl -s -XPOST http://dashboard.example:8080/api/agent -H "X-Key: $AGENT_KEY" \
  -d '{"name":"backup-bot","host":"Homeserver","status":"working","task":"verifying archives"}'
```

`status` is free text; `working`, `idle` and `offline` get their own colours. `host` groups agents; the sidebar pages expect `Homeserver` and `My Mac`, other values appear under Overview.

Other machines push their load, memory and disk with `report_mac.py` (macOS; run it every minute from launchd or cron), which feeds the "My Mac · System" page. `report_antigravity.py` lists the Antigravity agent on the Mac as working, idle or offline (run it every 30 seconds; it sends only the status and the working folder's name). `report_upload_job.py` reports the result of an offsite-upload job (rclone, rsync, ...) from its systemd unit; read the header of each script. The upload job uses `BACKUP_KEY`, everything else `AGENT_KEY`.

## Running it as a service

```ini
# /etc/systemd/system/agent-dashboard.service
[Unit]
Description=Agent dashboard
After=network-online.target

[Service]
User=dashboard
EnvironmentFile=/etc/agent-dashboard.env   # mode 600, see .env.example
StateDirectory=agent-dashboard             # /var/lib/agent-dashboard, writable for STATE_FILE even with ProtectSystem=strict
ExecStart=/usr/bin/python3 /opt/agent-dashboard/server.py
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## Security

- **There is no login for reading.** Anyone who can reach the port sees your VMs, storage, tasks and agents. The server listens on `127.0.0.1` by default. To serve other machines, set `BIND` deliberately and put it behind a reverse proxy with authentication and TLS, or keep it on a trusted network.
- **The keys travel in a header.** Over plain HTTP it can be read on the network. Use HTTPS (through the proxy) when the path is not trusted.
- **Use a read-only token** (`PVEAuditor`) and keep it in an environment file outside the repository. Never commit `.env`; `.gitignore` already excludes it.
- **Verify the Proxmox certificate** (`PVE_CA_FILE`). `PVE_TLS_VERIFY=0` removes the protection against someone impersonating Proxmox, so it belongs on a trusted LAN only.
- The dashboard only reads from Proxmox. It never starts, stops or changes anything.

## Tests

```sh
python3 -m unittest test_server -v
```

They check the access rules: POSTs are refused without the key, the safe defaults, and that VM ids are validated before they reach Proxmox.

## License

[MIT](LICENSE): use it, change it, share it, including commercially. The only condition is keeping the copyright notice and license text with copies of the code.
